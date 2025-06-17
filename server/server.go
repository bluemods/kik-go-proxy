package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bluemods/kik-go-proxy/antispam"
	"github.com/bluemods/kik-go-proxy/constants"
	"github.com/bluemods/kik-go-proxy/crypto"
	"github.com/bluemods/kik-go-proxy/node"
	"github.com/bluemods/kik-go-proxy/ratelimit"
	"github.com/bluemods/kik-go-proxy/server/connection"
	"github.com/bluemods/kik-go-proxy/utils"
)

type Server struct {
	config      *ServerConfig
	connections *KikConnectionHolder

	doneWaiter *sync.WaitGroup
}

// New builder for a server that will open a
// plain text connection on the given port.
func NewInsecure(port int) *ServerConfig {
	if port < 0 || port > 0xFFFF {
		log.Panicf("invalid port %d", port)
	}
	return &ServerConfig{
		listener: func() (net.Listener, error) {
			return net.Listen(constants.SERVER_TYPE, ":"+strconv.Itoa(port))
		},
		port: port,
		tls:  false,
	}
}

// New builder for a server that will open a
// TLS (secure) connection on the given port with the given config.
func NewTLS(port int, config *tls.Config) *ServerConfig {
	if port < 0 || port > 0xFFFF {
		log.Panicf("invalid port %d", port)
	}
	return &ServerConfig{
		listener: func() (net.Listener, error) {
			return tls.Listen(constants.SERVER_TYPE, ":"+strconv.Itoa(port), config)
		},
		port: port,
		tls:  true,
	}
}

// Awaits completion of the main loop, blocking the current goroutine.
func (s *Server) Await() {
	s.doneWaiter.Wait()
}

func (s *Server) start() {
	listener, err := s.config.listener()
	if err != nil {
		log.Println("failed to open socket", err)
		return
	}

	if s.config.tls {
		log.Printf("kik-go-proxy listening using \033[0;32mSSL\033[0m on :%d\n", s.config.port)
	} else {
		log.Printf("kik-go-proxy listening \033[0;31munencrypted\033[0m on :%d\n", s.config.port)
	}

	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting: " + err.Error())
		} else {
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	connId := s.connections.onConnected(clientConn)
	defer s.connections.onDisconnected(connId)

	ip := utils.ConnToIp(clientConn)

	clientConn.SetReadDeadline(time.Now().Add(constants.CLIENT_INITIAL_READ_TIMEOUT_SECONDS * time.Second))
	k, shouldBan, err := node.ParseInitialStreamTag(clientConn)

	if err != nil {
		if shouldBan {
			s.banIp(ip)
		}
		log.Println("Rejecting from " + ip + ": " + err.Error())
		return
	}
	k.ClientIp = ip

	if s.config.apiKey != nil && !s.isWhitelisted(k) {
		apiKey := k.ApiKey
		if apiKey == nil || len(*apiKey) == 0 {
			log.Println(ip + ": API key missing when required")
			s.banIp(ip)
			return
		}
		if !s.config.apiKey.Validate(*k.ApiKey) {
			log.Println(ip + ": API key mismatch")
			s.banIp(ip)
			return
		}
	}

	kikConn, err := s.dialKik(k)
	if err != nil {
		log.Printf("Failed to dial %s to Kik (IP: %s): %s\n", k.UserId(), ip, err.Error())
		return
	}
	defer kikConn.Close()

	var hasAccessToken string
	if !k.IsAuth {
		hasAccessToken = ""
	} else if k.AccessToken != nil {
		now := crypto.GetServerTimeAsTime()
		notAfter := k.AccessToken.NotAfter
		var expires string
		if now.After(notAfter) {
			expires = "\u001b[0;31m" + "expired at " + notAfter.String() + "\u001b[0m"
		} else {
			expires = "expires in " + notAfter.Sub(now).String()
		}
		hasAccessToken = " (access-token: \u001b[0;32m" + "yes, " + expires + "\u001b[0m)" // green
	} else {
		hasAccessToken = " (access-token: \u001b[0;31m" + "no" + "\u001b[0m)" // red
	}

	if kikConn.LocalAddr() != nil {
		log.Printf("Accepting %s (%s <=> %s)%s\n", k.UserId(), ip, kikConn.LocalAddr(), hasAccessToken)
	} else {
		log.Printf("Accepting %s (IP: %s)%s\n", k.UserId(), ip, hasAccessToken)
	}

	kikConn.SetDeadline(time.Now().Add(constants.KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second))

	var outgoingKTag string
	if s.config.customStreamInitFunc != nil {
		outgoingKTag = s.config.customStreamInitFunc(k)
	} else {
		outgoingKTag = k.RawStanza
	}
	if _, err = kikConn.Write([]byte(outgoingKTag)); err != nil {
		log.Println("Failed to write bind stanza:", err.Error())
		return
	}

	kikInput := node.NewNodeInputStream(kikConn)
	defer kikInput.Reader.ClearBuffer()

	kikResponse, err := node.ParseInitialStreamResponse(kikInput)
	if err != nil {
		log.Println("Failed to parse bind response:", err.Error())
		return
	}
	if _, err := clientConn.Write([]byte(kikResponse.GenerateServerResponse(s.config.customBanner))); err != nil {
		log.Println("Failed to write bind response to client:", err.Error())
		return
	}
	if !kikResponse.IsOk {
		log.Println("Kik rejected bind:", kikResponse.RawStanza)
		return
	}

	clientInput := node.NewNodeInputStream(clientConn)
	defer clientInput.Reader.ClearBuffer()

	c := &connection.KikProxyConnection{
		UserId:      k.UserId(),
		IsAuthed:    k.IsAuth,
		ClientConn:  clientConn,
		ClientInput: clientInput,
		KikConn:     kikConn,
		KikInput:    kikInput,
		RateLimiter: s.createRateLimiter(k),
		Logger:      s.createXmppLogger(k),
	}
	c.Run() // Blocks until connection is complete
}

func (s *Server) dialKik(k *node.InitialStreamTag) (*tls.Conn, error) {
	kikHost, err := k.KikHost()
	if err != nil {
		s.banIp(k.ClientIp)
		return nil, err
	}
	kikAddr := *kikHost + ":" + constants.KIK_SERVER_PORT
	config := tls.Config{
		ServerName: *kikHost,
		MinVersion: constants.SERVER_TLS_VERSION,
	}
	dialer := net.Dialer{
		Timeout: constants.KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second,
	}
	if interfaceIp := k.InterfaceIp; interfaceIp != nil {
		if s.config.ifaceMap == nil {
			return nil, errors.New("client requested to use interface when not available")
		}
		tcpAddr, found := s.config.ifaceMap[*interfaceIp]
		if !found {
			return nil, fmt.Errorf(
				"failed connecting via custom interface; '%s' not found in allowlist %v",
				*interfaceIp, s.config.ifaceMap)
		}
		dialer.LocalAddr = tcpAddr
	}
	if f := s.config.customDialerFunc; f != nil {
		return f(k, &dialer, constants.KIK_SERVER_TYPE, kikAddr, &config)
	}
	return tls.DialWithDialer(&dialer, constants.KIK_SERVER_TYPE, kikAddr, &config)
}

func (s *Server) isWhitelisted(k *node.InitialStreamTag) bool {
	_, ok := s.config.whitelist[k.UserId()]
	return ok
}

func (s *Server) createRateLimiter(k *node.InitialStreamTag) *ratelimit.KikRateLimiter {
	if s.config.antiSpamFunc == nil || !s.config.antiSpamFunc(k) {
		return nil
	}
	return ratelimit.NewRateLimiter()
}

func (s *Server) createXmppLogger(k *node.InitialStreamTag) *connection.XmppLogger {
	if s.config.xmppLogFunc == nil || !s.config.xmppLogFunc(k) {
		return nil
	}
	outPath := filepath.Join("xmpp", filepath.Clean(k.UserId()))
	logger, err := connection.NewXmppLogger(outPath)
	if err != nil {
		log.Println("failed to create XMPP logger: ", outPath)
		return nil
	}
	return logger
}

func (s *Server) banIp(ip string) {
	if s.config.autoBanHosts {
		antispam.BanIpAddress(ip)
		s.connections.DisconnectIp(ip)
	}
}

package server

import (
	"crypto/tls"
	"log"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/bluemods/kik-go-proxy/node"
)

type ServerConfig struct {
	listener             func() (net.Listener, error)
	apiKey               *ApiKey
	ifaceMap             map[string]*net.TCPAddr
	whitelist            map[string]struct{}
	autoBanHosts         bool
	antiSpamFunc         func(k *node.InitialStreamTag) bool
	xmppLogFunc          func(k *node.InitialStreamTag) bool
	customDialerFunc     func(k *node.InitialStreamTag, dialer *net.Dialer, network string, addr string, config *tls.Config) (*tls.Conn, error)
	customStreamInitFunc func(k *node.InitialStreamTag) string
	customBanner         bool
	port                 int
	tls                  bool
}

// When specified, only whitelisted accounts and
// clients that authenticate with
// the 'x-api-key' header matching the apiKey
// will be allowed to connect.
func (s *ServerConfig) WithApiKey(apiKey string) *ServerConfig {
	k := NewApiKey(apiKey)
	s.apiKey = &k
	return s
}

// Use a custom network interface to dial to Kik.
// allowedIps is the list of IPs that clients are
// allowed to use via the 'x-interface' stream header.
// Set to nil to allow all addresses under the iface.
func (s *ServerConfig) WithInterface(iface net.Interface, allowedIps []string) *ServerConfig {
	s.ifaceMap = map[string]*net.TCPAddr{}

	addrs, err := iface.Addrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP
			// Don't use loopback, private, or V6 IPs (Kik is V4 only)
			if !ip.IsPrivate() && !ip.IsLoopback() && ip.To4() != nil {
				if allowedIps == nil || slices.Contains(allowedIps, ip.String()) {
					s.ifaceMap[ip.String()] = &net.TCPAddr{IP: ip}
				}
			}
		}
	}

	sb := new(strings.Builder)
	for _, ip := range s.ifaceMap {
		sb.Write([]byte(ip.String()))
		sb.WriteByte(',')
	}
	log.Println("Using interface " + iface.Name + " (Extra IPs: " + sb.String() + ")")
	return s
}

// JIDs / device IDs on this list aren't subject to API key restrictions.
func (s *ServerConfig) WithWhitelist(whitelist []string) *ServerConfig {
	s.whitelist = map[string]struct{}{}
	for _, id := range whitelist {
		s.whitelist[id] = struct{}{}
	}
	return s
}

// Hosts will be banned using iptables
// if they send malformed packets,
// fail integrity checks or are IP scrapers
func (s *ServerConfig) WithBanHosts() *ServerConfig {
	s.autoBanHosts = true
	return s
}

// All clients will be protected by rate limiting.
// If a peer sends too many messages to the client,
// the server will intercept and delete them.
func (s *ServerConfig) WithAntiSpam() *ServerConfig {
	return s.WithAntiSpamFunc(func(*node.InitialStreamTag) bool { return true })
}

// All clients matching f will be protected by rate limiting.
// If a peer sends too many messages to the client,
// the server will intercept and delete them.
func (s *ServerConfig) WithAntiSpamFunc(f func(k *node.InitialStreamTag) bool) *ServerConfig {
	s.antiSpamFunc = f
	return s
}

// Server logs all XMPP sent and received to the 'xmpp' directory.
func (s *ServerConfig) WithXmppLogging() *ServerConfig {
	return s.WithAntiSpamFunc(func(*node.InitialStreamTag) bool { return true })
}

// Server logs all XMPP sent and received to the 'xmpp' directory
// for all clients matching f
func (s *ServerConfig) WithXmppLoggingFunc(f func(k *node.InitialStreamTag) bool) *ServerConfig {
	s.xmppLogFunc = f
	return s
}

// Server will include a banner in the
// stream header upon successful authentication.
func (s *ServerConfig) WithCustomBanner() *ServerConfig {
	s.customBanner = true
	return s
}

// Server will use your custom dialer to connect to Kik.
//
// dialer, network, addr, and config can be used to call tls.DialWithDialer.
func (s *ServerConfig) WithCustomDialer(f func(k *node.InitialStreamTag, dialer *net.Dialer, network string, addr string, config *tls.Config) (*tls.Conn, error)) *ServerConfig {
	s.customDialerFunc = f
	return s
}

// Server will use your custom dialer to connect to Kik.
//
// dialer, network, addr, and config can be used to call tls.DialWithDialer.
func (s *ServerConfig) WithInitStreamTagGenerator(f func(k *node.InitialStreamTag) string) *ServerConfig {
	s.customStreamInitFunc = f
	return s
}

// Starts the server.
// Call Server.Await() to block, which is required for CLI.
func (s *ServerConfig) Start() *Server {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	server := &Server{config: s, connections: NewConnectionHolder(), doneWaiter: wg}
	go func() {
		defer wg.Done()
		server.start()
	}()
	return server
}

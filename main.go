package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bluemods/kik-go-proxy/antispam"
	"github.com/bluemods/kik-go-proxy/connection"
	"github.com/bluemods/kik-go-proxy/constants"
	"github.com/bluemods/kik-go-proxy/node"
	"github.com/bluemods/kik-go-proxy/ratelimit"
	"github.com/bluemods/kik-go-proxy/utils"
	"golang.org/x/crypto/pkcs12"
)

var (
	API_KEY_REGEX *regexp.Regexp = regexp.MustCompile(fmt.Sprintf(
		"^[A-Za-z0-9._-]{%d,%d}$",
		constants.API_KEY_MIN_LENGTH,
		constants.API_KEY_MAX_LENGTH))

	// We store this as a SHA-256 hash for security purposes.
	// You can start the server, delete the file,
	// then the API key should be unrecoverable from the program
	currentHashedApiKey []byte = make([]byte, 0)

	interfaceIps  []string = make([]string, 0)
	interfaceName string   = constants.DEFAULT_INTERFACE_NAME

	whitelist map[string]struct{} = map[string]struct{}{}

	autoBanHosts bool = false
	antiSpam     bool = false

	customBanner bool = false
	iosMode      bool = false

	ConnectionInfo *utils.KikConnectionInfo = utils.NewConnectionInfo()
)

func main() {
	port := flag.String("port", "", "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file, must be used with -key")
	keyFile := flag.String("key", "", "key PEM file, must be used with -cert")
	p12File := flag.String("p12", "", ".p12 certificate file, must be used with -p12-pass")
	p12PasswordFile := flag.String("p12-pass", "", "file containing the .p12 certificate password, must be used with -p12")
	ipFile := flag.String("i", "", "file containing list of interface IPs, one per line")
	iname := flag.String("iname", "", "the interface name to use, only meaningful with -i. Defaults to eth0")
	apiKeyFile := flag.String("a", "", "file containing the API key that all clients must authenticate with (using x-api-key attribute in <k header)")
	whitelistFile := flag.String("whitelist", "", "file containing JIDs / device IDs that do not require API key authentication, one per line")
	banHosts := flag.Bool("ban", false, "if true, misbehaving clients are IP banned from the server using iptables")
	antiSpamFlag := flag.Bool("spam", false, "if true, incoming spam will be intercepted and blocked")
	customBannerFlag := flag.Bool("banner", false, "if true, the server sends back a 'server' header upon successful authentication")
	iosModeFlag := flag.Bool("ios", false, "if true, the server will transform packets to the iOS protocol. Note that this will not work out of the box, you must code it yourseld (see ios_registry.go)")
	flag.Parse()

	// profiling.OpenProfileServer("40001")

	autoBanHosts = *banHosts
	antiSpam = *antiSpamFlag
	customBanner = *customBannerFlag
	iosMode = *iosModeFlag

	if *iname != "" {
		log.Println("Using custom interface name " + *iname)
		interfaceName = *iname
	}
	err := parseApiKeyFile(*apiKeyFile)
	if err != nil {
		log.Fatal("Failed parsing API key file: ", err.Error())
	}
	err = parseDelimitedFile(*ipFile, func(ip string) {
		interfaceIps = append(interfaceIps, ip)
	})
	if err != nil {
		log.Fatal("Failed parsing interface file: ", err.Error())
	}
	err = parseDelimitedFile(*whitelistFile, func(userId string) {
		whitelist[userId] = struct{}{}
	})
	if err != nil {
		log.Fatal("Failed parsing whitelist file: ", err.Error())
	}

	if *p12File != "" && *p12PasswordFile != "" {
		cert, err := loadP12Cert(*p12File, *p12PasswordFile)
		if err != nil {
			log.Fatal("Error loading .p12 certificate:", err.Error())
		}
		if *port == "" {
			openSSLServer(constants.SSL_SERVER_PORT, *cert)
		} else {
			openSSLServer(*port, *cert)
		}
	} else if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatal("Error loading key pair: ", err.Error())
		}
		if *port == "" {
			openSSLServer(constants.SSL_SERVER_PORT, cert)
		} else {
			openSSLServer(*port, cert)
		}
	} else {
		if *port == "" {
			openPlainServer(constants.PLAIN_SERVER_PORT)
		} else {
			openPlainServer(*port)
		}
	}
}

func loadP12Cert(p12File string, p12PasswordFile string) (*tls.Certificate, error) {
	p12Bytes, err := os.ReadFile(p12File)
	if err != nil {
		return nil, err
	}
	p12Password, err := os.ReadFile(p12PasswordFile)
	if err != nil {
		return nil, err
	}
	// This way supports more p12 certs, as not all of them
	// will have exactly two safe bags in the PFX PDU
	blocks, err := pkcs12.ToPEM(p12Bytes, string(p12Password))
	// Explicitly zero the password array
	for i := range p12Password {
		p12Password[i] = 0
	}
	if err != nil {
		return nil, err
	}

	var pemData []byte
	for _, block := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func parseApiKeyFile(apiKeyFile string) error {
	if apiKeyFile == "" {
		return nil
	}
	stat, err := os.Stat(apiKeyFile)

	if err != nil {
		return err
	}
	fileSize := stat.Size()
	if fileSize > 1024 {
		return fmt.Errorf(
			"API key file %s is too large (%d > %d)", apiKeyFile, fileSize, 1024)
	}

	apiKeyBytes, err := os.ReadFile(apiKeyFile)
	if err != nil {
		return err
	}
	apiKey := strings.Trim(string(apiKeyBytes), " \r\n")
	if !API_KEY_REGEX.MatchString(apiKey) {
		return fmt.Errorf(
			"API key at %s doesn't match regex `%s`", apiKeyFile, API_KEY_REGEX.String())
	}
	log.Printf("API key set (length=%d)\n", len(apiKey))
	currentHashedApiKey = hashApiKey(apiKey)
	return nil
}

func hashApiKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

func parseDelimitedFile(filePath string, collector func(string)) error {
	if filePath == "" {
		return nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")

		// This allows us to include comments like
		// your_value # comment here
		i := strings.Index(line, "#")
		if i != -1 {
			line = line[:i]
		}
		line = strings.Trim(line, " ")
		collector(line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func openSSLServer(port string, cert tls.Certificate) {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   constants.SERVER_TLS_VERSION,
	}
	server, err := tls.Listen(constants.SERVER_TYPE, ":"+port, config)
	if err != nil {
		log.Fatal("Error opening SSL socket: ", err.Error())
	}
	defer server.Close()
	log.Println("Listening using SSL on :" + port)
	for {
		connection, err := server.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
		} else {
			go handleNewConnection(connection)
		}
	}
}

func openPlainServer(port string) {
	server, err := net.Listen(constants.SERVER_TYPE, ":"+port)
	if err != nil {
		log.Fatal("Error opening unencrypted socket:" + err.Error())
	}
	defer server.Close()
	log.Println("Listening unencrypted on :" + port)
	for {
		connection, err := server.Accept()
		if err != nil {
			log.Println("Error accepting: " + err.Error())
		} else {
			go handleNewConnection(connection)
		}
	}
}

func handleNewConnection(clientConn net.Conn) {
	defer clientConn.Close()
	connId := ConnectionInfo.AddConnection(clientConn)
	defer ConnectionInfo.RemoveConnection(connId)

	ip, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		// Shouldn't happen but being safe
		log.Println("Rejecting connection, could not parse remote IP address")
		return
	}

	clientConn.SetReadDeadline(time.Now().Add(constants.CLIENT_INITIAL_READ_TIMEOUT_SECONDS * time.Second))
	k, shouldBan, err := node.ParseInitialStreamTag(clientConn)

	if err != nil {
		if shouldBan {
			banIp(ip)
		}
		log.Println("Rejecting from " + ip + ": " + err.Error())
		return
	}
	if !isWhitelisted(k) && len(currentHashedApiKey) > 0 {
		apiKey := k.ApiKey
		if apiKey == nil {
			log.Println(ip + ": API key missing when required")
			banIp(ip)
			return
		}
		if len(*apiKey) < constants.API_KEY_MIN_LENGTH || len(*apiKey) > constants.API_KEY_MAX_LENGTH {
			log.Println(ip + ": Invalid API key length")
			banIp(ip)
			return
		}
		userHashedApiKey := hashApiKey(*apiKey)

		// Constant time compare defends against timing attacks.
		// Hashes always are the same length so ConstantTimeEq is unnecessary
		if subtle.ConstantTimeCompare(userHashedApiKey, currentHashedApiKey) != 1 {
			log.Println(ip + ": API key mismatch")
			banIp(ip)
			return
		}
	}

	kikConn, err := dialKik(k)
	if err != nil {
		log.Println("Failed to dial " + k.GetUserId() + " to Kik (IP:" + ip + "): " + err.Error())
		return
	}
	defer kikConn.Close()

	if kikConn.LocalAddr() != nil {
		log.Printf("Accepting %s (%s <=> %s)\n", k.GetUserId(), ip, kikConn.LocalAddr())
	} else {
		log.Printf("Accepting %s (IP: %s)\n", k.GetUserId(), ip)
	}

	kikConn.SetDeadline(time.Now().Add(constants.KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second))

	if _, err = kikConn.Write([]byte(k.GenerateStreamInitTag(iosMode))); err != nil {
		log.Println("Failed to write bind stanza: " + err.Error())
		return
	}

	kikInput := node.NewNodeInputStream(kikConn)
	defer kikInput.Reader.ClearBuffer()
	kikResponse, err := node.ParseInitialStreamResponse(kikInput)
	if err != nil {
		log.Println("Failed to parse bind response: " + err.Error())
		return
	}
	clientConn.Write([]byte(kikResponse.GenerateServerResponse(customBanner)))
	if !kikResponse.IsOk {
		log.Println("Kik rejected bind: " + kikResponse.RawStanza)
		return
	}

	clientInput := node.NewNodeInputStream(clientConn)
	defer clientInput.Reader.ClearBuffer()

	var rateLimiter *ratelimit.KikRateLimiter
	if antiSpam {
		rateLimiter = ratelimit.CreateRateLimiter()
	}
	var logger *connection.XmppLogger
	if isXmppLoggerEligible(k) {
		// TODO output destination process is outstanding
		outPath := filepath.Join("xmpp", filepath.Clean(k.GetUserId()))
		if logger, err = connection.NewXmppLogger(outPath); err != nil {
			log.Println("failed to create logger: " + outPath)
		}
	}

	c := &connection.KikProxyConnection{
		UserId:      k.GetUserId(),
		IsAuthed:    k.IsAuth,
		ClientConn:  clientConn,
		ClientInput: clientInput,
		KikConn:     kikConn,
		KikInput:    kikInput,
		RateLimiter: rateLimiter,
		Logger:      logger,
	}
	c.Run() // Blocks until connection is complete
}

func dialKik(payload *node.InitialStreamTag) (*tls.Conn, error) {
	minVer := ConnectionInfo.MinTlsVersion
	maxVer := ConnectionInfo.MaxTlsVersion

	config := tls.Config{
		ServerName: ConnectionInfo.CerificateHost,
		MinVersion: *minVer,
		MaxVersion: *maxVer,
	}

	var dialer net.Dialer
	if payload.InterfaceIp != nil {
		if !slices.Contains(interfaceIps, *payload.InterfaceIp) {
			err := errors.New("Client requested to use unknown interface " +
				*payload.InterfaceIp + ", aborting connection")
			return nil, err
		}
		netInterface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			ifaces, netErr := net.Interfaces()
			if netErr != nil {
				return nil, netErr
			} else {
				msg := "Missing interface, we can select from: "
				for _, s := range ifaces {
					msg += s.Name + ","
				}
				return nil, errors.New(msg + " | " + err.Error())
			}
		}
		addrs, err := netInterface.Addrs()
		if err != nil {
			return nil, err
		}

		var selectedIP net.IP

		for i := 0; i < len(addrs); i++ {
			ip := addrs[i].(*net.IPNet).IP
			if ip.String() == *payload.InterfaceIp {
				selectedIP = ip
				break
			}
		}
		if selectedIP == nil {
			return nil, errors.New("Failed connecting via custom interface; '" + *payload.InterfaceIp + "' not found in " + interfaceName)
		}

		tcpAddr := &net.TCPAddr{
			IP: selectedIP,
		}
		dialer = net.Dialer{
			LocalAddr: tcpAddr,
			Timeout:   constants.KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second,
		}
	} else {
		dialer = net.Dialer{
			Timeout: constants.KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second,
		}
	}
	return tls.DialWithDialer(&dialer, constants.KIK_SERVER_TYPE, *ConnectionInfo.Host+":"+*ConnectionInfo.Port, &config)
}

func isXmppLoggerEligible(k *node.InitialStreamTag) bool {
	// TODO eligibility determination process is outstanding
	return false
}

func isWhitelisted(k *node.InitialStreamTag) bool {
	_, ok := whitelist[k.GetUserId()]
	return ok
}

func banIp(ip string) {
	if autoBanHosts {
		antispam.BanIpAddress(ip)
		ConnectionInfo.RemoveAllConnectionsByIp(ip)
	}
}

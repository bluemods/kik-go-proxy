package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// Default plaintext port
	PLAIN_SERVER_PORT = "5222"
	// Default SSL port
	SSL_SERVER_PORT = "5223"
	// Listen on IPV4. Kik requires IPV4 so it should be no issue
	SERVER_TYPE = "tcp4"
	// Client has this long to prove itself
	CLIENT_INITIAL_READ_TIMEOUT_SECONDS = 2
	// After initial read, abort if no data from client after this many seconds
	CLIENT_READ_TIMEOUT_SECONDS = 180

	// Host from 15.59.x on Android. All of them resolve to the same IPs, but we will use a newer version anyway
	KIK_HOST = "talk15590an.kik.com"
	// You can use port 443 or 5223 here, they behave the same
	KIK_PORT = "443"
	// Kik uses TCP
	KIK_SERVER_TYPE = "tcp"
	// Abort if Kik takes longer than this to send back the initial response
	KIK_INITIAL_READ_TIMEOUT_SECONDS = 5

	// TLSv1.2 is recommended for compatibility reasons.
	// If you don't need to support 1.2 clients, change to `tls.VersionTLS13`
	// DO NOT use lower than 1.2, as older protocols contain security flaws.
	SERVER_TLS_VERSION = tls.VersionTLS12

	DEFAULT_INTERFACE_NAME = "eth0"

	API_KEY_MIN_LENGTH = 32
	API_KEY_MAX_LENGTH = 256

	CUSTOM_BANNER = false
)

var (
	API_KEY_PATTERN string         = "^[A-Za-z0-9._-]{" + strconv.Itoa(API_KEY_MIN_LENGTH) + "," + strconv.Itoa(API_KEY_MAX_LENGTH) + "}$"
	API_KEY_REGEX   *regexp.Regexp = regexp.MustCompile(API_KEY_PATTERN)
	IPV4_REGEX      *regexp.Regexp = regexp.MustCompile(
		`^((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.` +
			`(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))$`)

	// We store this as a SHA-256 hash for security purposes.
	// You can start the server, delete the file,
	// then the API key should be unrecoverable from the program
	currentHashedApiKey []byte = make([]byte, 0)

	interfaceIps  []string = make([]string, 0)
	interfaceName string   = DEFAULT_INTERFACE_NAME

	autoBanHosts bool = false
	antiSpam     bool = false
)

func main() {
	port := flag.String("port", "", "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file")
	keyFile := flag.String("key", "", "key PEM file")
	ipFile := flag.String("i", "", "file containing list of interface IPs, one per line")
	iname := flag.String("iname", "", "the interface name to use, only meaningful with -i. Defaults to eth0")
	apiKeyFile := flag.String("a", "", "file containing the API key that all clients must authenticate with (using x-api-key attribute in <k header)")
	banHosts := flag.Bool("ban", false, "if true, misbehaving clients are IP banned from the server using iptables")
	antiSpamFlag := flag.Bool("spam", false, "if true, incoming spam will be intercepted and blocked")
	flag.Parse()

	autoBanHosts = *banHosts
	antiSpam = *antiSpamFlag

	if *iname != "" {
		log.Println("Using custom interface name " + *iname)
		interfaceName = *iname
	}
	err := parseApiKeyFile(*apiKeyFile)
	if err != nil {
		log.Fatal("Failed parsing API key file: ", err.Error())
	}
	err = parseInterfaceFile(*ipFile)
	if err != nil {
		log.Fatal("Failed parsing interface file: ", err.Error())
	}

	if *certFile != "" && *keyFile != "" {
		if *port == "" {
			openSSLServer(SSL_SERVER_PORT, *certFile, *keyFile)
		} else {
			openSSLServer(*port, *certFile, *keyFile)
		}
	} else {
		if *port == "" {
			openPlainServer(PLAIN_SERVER_PORT)
		} else {
			openPlainServer(*port)
		}
	}
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
			"API key in %s doesn't match regex `%s`", apiKey, API_KEY_PATTERN)
	}
	log.Printf("API key set (length=%d)\n", len(apiKey))
	currentHashedApiKey = hashApiKey(apiKey)
	return nil
}

func hashApiKey(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hash := hasher.Sum(nil)
	return hash
}

func parseInterfaceFile(ipFile string) error {
	if ipFile == "" {
		return nil
	}
	file, err := os.Open(ipFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		ip := strings.Trim(scanner.Text(), " ")

		// This allows us to include comments like
		// 1.1.1.1 # comment here
		i := strings.Index(ip, "#")
		if i != -1 {
			ip = strings.Trim(ip[:i], " ")
		}
		interfaceIps = append(interfaceIps, ip)
		log.Println("Adding interface IP " + ip)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func openSSLServer(port string, certFile string, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Error loading key pair:", err.Error())
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: SERVER_TLS_VERSION}
	server, err := tls.Listen(SERVER_TYPE, ":"+port, config)
	if err != nil {
		log.Fatal("Error opening SSL socket:", err.Error())
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
	server, err := net.Listen(SERVER_TYPE, ":"+port)
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

	ipAddress, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		// Shouldn't happen but being safe
		log.Println("Rejecting connection, could not parse remote IP address")
		return
	}

	clientConn.SetReadDeadline(time.Now().Add(CLIENT_INITIAL_READ_TIMEOUT_SECONDS * time.Second))
	k, shouldBan, err := ParseInitialStreamTag(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))

	if err != nil {
		if shouldBan {
			BanHost(ipAddress)
		}
		log.Println("Rejecting from " + ipAddress + ": " + err.Error())
		return
	}
	payload, err := k.MakeOutgoingPayload()
	if err != nil {
		log.Println("Failed validation " + ipAddress + ": " + err.Error())
		BanHost(ipAddress)
		return
	}
	if !isExempted(k) && len(currentHashedApiKey) > 0 {
		if len(payload.ApiKey) == 0 {
			log.Println(ipAddress + ": API key missing when required")
			BanHost(ipAddress)
			return
		}
		if len(payload.ApiKey) < API_KEY_MIN_LENGTH || len(payload.ApiKey) > API_KEY_MAX_LENGTH {
			log.Println(ipAddress + ": Invalid API key length")
			BanHost(ipAddress)
			return
		}
		userHashedApiKey := hashApiKey(payload.ApiKey)

		// Constant time compare defends against timing attacks.
		// Hashes always are the same length so ConstantTimeEq is unnecessary
		if subtle.ConstantTimeCompare(userHashedApiKey, currentHashedApiKey) != 1 {
			log.Println(ipAddress + ": API key mismatch")
			BanHost(ipAddress)
			return
		}
	}

	log.Printf("Accepting %s (IP: %s)\n", k.GetUserId(), ipAddress)

	kikConn, err := connectToKik(clientConn, payload)
	if err != nil {
		log.Println("Failed to connect " + ipAddress + " to Kik: " + err.Error())
		return
	}

	defer kikConn.Close()

	go proxy(false, kikConn, clientConn)
	proxy(true, clientConn, kikConn)
}

func BanHost(ipAddress string) {
	if !autoBanHosts {
		return
	}
	if !IPV4_REGEX.MatchString(ipAddress) {
		// This is ultra defensive programming
		// to make sure no bad values can be passed to the command
		log.Printf("Can't ban IP %s; doesn't match IPV4 regex", ipAddress)
		return
	}
	command := exec.Command("iptables", "-A", "INPUT", "-s", ipAddress, "-j", "DROP")
	stdout, err := command.Output()
	if err != nil {
		log.Println("Failed to ban " + ipAddress + ": " + err.Error())
	} else {
		log.Println("Banned " + ipAddress + ": " + string(stdout))
	}
}

func isExempted(k *InitialStreamTag) bool {
	// You can add exemptions to API key rule here
	return false
}

func proxy(fromIsClient bool, from net.Conn, to net.Conn) {
	inputStream := CreateNodeInputStream(from)
	defer inputStream.Reader.ClearBuffer()

	var rateLimiter *KikRateLimiter = nil
	if !fromIsClient && antiSpam {
		rateLimiter = CreateRateLimiter()
	}

	for {
		node, stanza, err := inputStream.ReadNextStanza()

		if err != nil {
			if rateLimiter != nil {
				rateLimiter.FlushMessages(from)
			}
			errMessage := err.Error()

			if strings.HasPrefix(errMessage, "XML syntax error") {
				if strings.HasSuffix(errMessage, "unexpected end element </k>") {
					// XML parser currently treats it like an error.
					// Send it manually to properly close connection
					to.Write([]byte("</k>"))
				} else {
					// Log unexpected XML parsing errors
					log.Println(
						"Unexpected XML parsing error:\n" +
							err.Error() + "\nStanza:\n" + inputStream.Reader.GetBuffer())
				}
			}
			return
		}

		if rateLimiter != nil {
			blocked := rateLimiter.ProcessMessage(from, *node)
			if blocked {
				continue
			}
		}

		to.Write([]byte(*stanza))
		from.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))
	}
}

func connectToKik(clientConn net.Conn, payload *OutgoingKPayload) (*tls.Conn, error) {
	config := tls.Config{ServerName: KIK_HOST}

	var dialer net.Dialer
	if payload.InterfaceIp != "" {
		if !slices.Contains(interfaceIps, payload.InterfaceIp) {
			err := errors.New("Client requested to use unknown interface " +
				payload.InterfaceIp + ", aborting connection")
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
			if ip.String() == payload.InterfaceIp {
				selectedIP = ip
				break
			}
		}
		if selectedIP == nil {
			return nil, errors.New("Failed connecting via custom interface; '" + payload.InterfaceIp + "' not found in " + interfaceName)
		}

		tcpAddr := &net.TCPAddr{
			IP: selectedIP,
		}
		dialer = net.Dialer{
			LocalAddr: tcpAddr,
			Timeout:   KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second,
		}
	} else {
		dialer = net.Dialer{
			Timeout: KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second,
		}
	}

	kikConn, err := tls.DialWithDialer(&dialer, KIK_SERVER_TYPE, KIK_HOST+":"+KIK_PORT, &config)
	if err != nil {
		return nil, err
	}
	kikConn.Write([]byte(payload.RawStanza))
	kikConn.SetReadDeadline(time.Now().Add(KIK_INITIAL_READ_TIMEOUT_SECONDS * time.Second))
	kikResponse, err := ParseInitialStreamResponse(kikConn)
	if err != nil {
		return nil, err
	}
	clientConn.Write([]byte(kikResponse.GenerateServerResponse()))
	if !kikResponse.IsOk {
		return nil, errors.New("Kik rejected bind: " + kikResponse.RawStanza)
	}
	return kikConn, nil
}

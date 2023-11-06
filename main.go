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
	CLIENT_READ_TIMEOUT_SECONDS = 30

	// Host from 15.59.x on Android. All of them resolve to the same IPs, but we will use a newer version anyway
	KIK_HOST = "talk15590an.kik.com"
	// You can use port 443 or 5223 here, they behave the same
	KIK_PORT = "443"
	// Kik uses TCP
	KIK_SERVER_TYPE = "tcp"
	// Abort if Kik takes longer than this to send back the initial response
	KIK_INITIAL_READ_TIMEOUT_SECONDS = 5

	// The buffer size for the client and kik socket
	SOCKET_BUFFER_SIZE = 8192

	// TLSv1.3 is recommended.
	// If you have clients that don't support 1.3,
	// change to tls.VersionTLS12
	SERVER_TLS_VERSION = tls.VersionTLS13

	DEFAULT_INTERFACE_NAME = "eth0"

	API_KEY_MIN_LENGTH = 32
	API_KEY_MAX_LENGTH = 256

	CUSTOM_BANNER = false
)

// If supplied as an argument, the API key must match this regex for the connection to proceed.
// The server will strip this key before sending the stanza to Kik.
// Example: <k from="some_user@talk.kik.com" x-api-key="YOUR_API_KEY">
// You should randomly generate this string.
// The character set is restricted to characters safe for XML attribute values.
var API_KEY_PATTERN string = "^[A-Za-z0-9._-]{" + strconv.Itoa(API_KEY_MIN_LENGTH) + "," + strconv.Itoa(API_KEY_MAX_LENGTH) + "}$"

var API_KEY_REGEX *regexp.Regexp = regexp.MustCompile(API_KEY_PATTERN)

// We store this as a SHA-256 hash for security purposes.
var currentHashedApiKey []byte = make([]byte, 0)

var interfaceIps []string = make([]string, 0)
var interfaceName = DEFAULT_INTERFACE_NAME

func main() {
	port := flag.String("port", "", "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file")
	keyFile := flag.String("key", "", "key PEM file")
	ipFile := flag.String("i", "", "file containing list of interface IPs, one per line")
	iname := flag.String("iname", "", "the interface name to use, only meaningful with -i. Defaults to eth0")
	apiKeyFile := flag.String("a", "", "file containing the API key that all clients must authenticate with (using x-api-key attribute in <k header)")
	flag.Parse()

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
		return errors.New(fmt.Sprintf(
			"API key file %s is too large (%d > %d)", apiKeyFile, fileSize, 1024))
	}

	apiKeyBytes, err := os.ReadFile(apiKeyFile)
	if err != nil {
		return err
	}
	apiKey := strings.Trim(string(apiKeyBytes), " \r\n")
	if !API_KEY_REGEX.MatchString(apiKey) {
		return errors.New(fmt.Sprintf(
			"API key in %s doesn't match regex `%s`", apiKey, API_KEY_PATTERN))
	}
	log.Printf("API key set (length=%d)\n", len(apiKey))
	currentHashedApiKey = hashApiKey(apiKey)
	return nil
}

func hashApiKey(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hash := hasher.Sum([]byte{})
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
	ipAddress, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		// Shouldn't happen but being safe
		log.Println("Rejecting connection, could not parse remote IP address")
		clientConn.Close()
		return
	}

	k, err := readKFromClient(clientConn)
	if err != nil {
		// TODO: ban hosts
		log.Println("Rejecting from " + ipAddress + ": " + err.Error())
		clientConn.Close()
		return
	}
	payload, err := k.makeOutgoingPayload()
	if err != nil {
		// TODO: ban hosts
		log.Println("Failed validation " + ipAddress + ": " + err.Error())
		clientConn.Close()
		return
	}
	if len(currentHashedApiKey) > 0 {
		if len(payload.ApiKey) == 0 {
			// TODO: ban hosts
			log.Println(ipAddress + ": API key missing when required")
			clientConn.Close()
			return
		}
		if len(payload.ApiKey) < API_KEY_MIN_LENGTH || len(payload.ApiKey) > API_KEY_MAX_LENGTH {
			// TODO: ban hosts
			log.Println(ipAddress + ": Invalid API key length")
			clientConn.Close()
			return
		}
		userHashedApiKey := hashApiKey(payload.ApiKey)

		// Constant time compare defends against timing attacks.
		// Hashes always are the same length so ConstantTimeEq is unnecessary
		if subtle.ConstantTimeCompare(userHashedApiKey, currentHashedApiKey) != 1 {
			// TODO: ban hosts
			log.Println(ipAddress + ": API key mismatch")
			clientConn.Close()
			return
		}
	}

	if jid, ok := k.Attributes["from"]; ok {
		log.Printf("Accepting %s (IP: %s)\n", strings.Split(jid, "/")[0], ipAddress)
	} else if deviceId, ok := k.Attributes["dev"]; ok {
		log.Printf("Accepting pre-authenticated user %s (IP: %s)\n", deviceId, ipAddress)
	} else {
		log.Printf("%s is missing a from or dev attribute in initial stream tag\n", ipAddress)
		clientConn.Close()
		return
	}

	kikConn, err := connectToKik(clientConn, payload)
	if err != nil {
		log.Println("Failed to connect " + ipAddress + " to Kik: " + err.Error())
		clientConn.Close()
		return
	}

	go proxy(clientConn, kikConn)
	proxy(kikConn, clientConn)
}

/*func proxy(from net.Conn, to net.Conn) {
	buf := make([]byte, SOCKET_BUFFER_SIZE)

	defer from.Close()
	defer to.Close()

	for {
		read, err := from.Read(buf)
		if err != nil {
			return
		}
		to.Write(buf[0:read])
		from.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))
	}
}*/

func proxy(from net.Conn, to net.Conn) {
	defer from.Close()
	defer to.Close()

	inputStream := createParser(from)
	defer inputStream.Reader.ClearBuffer()

	for {
		_, stanza, err := inputStream.readNextStanza()
		// node, stanza, err := inputStream.readNextStanza()
		// Here you can log the stanza, change the contents, etc
		// before forwarding it on to the recipient

		if err != nil {
			errMessage := err.Error()

			if strings.HasPrefix(errMessage, "XML syntax error") {
				if strings.HasSuffix(errMessage, "unexpected end element </k>") {
					// XML parser currently treats it like an error,
					// send it manually before closing
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
		// log.Println("Got " + *stanza)
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
	kikConn.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))
	kikConn.Write([]byte(payload.RawStanza))
	kikResponse, err := readKFromKik(kikConn)
	if err != nil {
		return nil, err
	}
	clientConn.Write([]byte(kikResponse.generateServerResponse()))
	if !kikResponse.IsOk {
		return nil, errors.New("Kik rejected bind: " + kikResponse.RawStanza)
	}
	return kikConn, nil
}

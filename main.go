package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"os"
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

	INTERFACE_NAME = "eth0"

	CUSTOM_BANNER = false
)

var interfaceIps []string = make([]string, 0)

func main() {
	port := flag.String("port", "", "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file")
	keyFile := flag.String("key", "", "key PEM file")
	ipFile := flag.String("i", "", "file containing list of interface IPs, one per line")
	flag.Parse()

	err := parseInterfaceFile(*ipFile)
	if err != nil {
		log.Fatal("Failed parsing interface file:", err.Error())
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

func parseInterfaceFile(ipFile string) error {
	file, err := os.Open(ipFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		ip := strings.Trim(scanner.Text(), " ")
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

	log.Println("Accepting from " + ipAddress + ": " + k.RawStanza)
	kikConn, err := connectToKik(clientConn, *payload, &k.InterfaceName)
	if err != nil {
		log.Println("Failed to connect " + ipAddress + " to Kik: " + err.Error())
		clientConn.Close()
		return
	}

	go proxy(clientConn, kikConn)
	proxy(kikConn, clientConn)
}

// For now, both methods simply copy
// the packets to each others streams, making a blind proxy
// (past the initial stream tags)

func proxy(from net.Conn, to net.Conn) {
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
}

func connectToKik(clientConn net.Conn, sortedKTag string, interfaceIp *string) (*tls.Conn, error) {
	config := tls.Config{ServerName: KIK_HOST}

	var dialer net.Dialer
	if interfaceIp != nil && *interfaceIp != "" {
		netInterface, err := net.InterfaceByName(INTERFACE_NAME)
		if err != nil {
			return nil, err
		}
		addrs, err := netInterface.Addrs()
		if err != nil {
			return nil, err
		}

		var selectedIP net.IP

		for i := 0; i < len(addrs); i++ {
			ip := addrs[i].(*net.IPNet).IP
			if ip.String() == *interfaceIp {
				selectedIP = ip
				break
			}
		}
		if selectedIP == nil {
			return nil, errors.New("Failed connecting via custom interface; '" + *interfaceIp + "' not found in " + INTERFACE_NAME)
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
	kikConn.Write([]byte(sortedKTag))
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

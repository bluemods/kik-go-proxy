package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
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
	// Kik has 443 and 5223 open, both behave identically
	KIK_PORT = "443"
	// Kik uses TCP
	KIK_SERVER_TYPE = "tcp"
	// Kik shouldn't take longer than 5s to respond. If it does, abort
	KIK_INITIAL_READ_TIMEOUT_SECONDS = 5

	// The buffer size for the client and kik socket
	SOCKET_BUFFER_SIZE = 8192

	CUSTOM_BANNER = false
)

func main() {
	port := flag.String("port", "", "Port to listen for incoming connections on")
	certFile := flag.String("cert", "", "certificate PEM file")
	keyFile := flag.String("key", "", "key PEM file")
	flag.Parse()

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

func openSSLServer(port string, certFile string, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Error loading key pair:", err.Error())
	}
	// Only accepting TLSv1.3 for now, as it's the most secure.
	// All modern clients should support this.
	// If it's an issue, change it to VersionTLS12
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
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
	kikConn, err := connectToKik(clientConn, *payload, "" /* TODO */)
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

func connectToKik(clientConn net.Conn, sortedKTag string, interfaceName string) (*tls.Conn, error) {
	config := tls.Config{ServerName: KIK_HOST}

	var dialer net.Dialer
	if interfaceName != "" {
		netInterface, err := net.InterfaceByName("eth0")
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
			if ip.String() == interfaceName {
				selectedIP = ip
				break
			}
		}
		if selectedIP == nil {
			return nil, errors.New("Failed connecting via custom interface; '" + interfaceName + "' not found")
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

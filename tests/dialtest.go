package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	TEST_SERVER_TYPE = "tcp"
	TEST_SERVER_HOST = "ip.me"
	TEST_SERVER_PORT = "443"
)

func main() {
	interfaceName := flag.String("i", "", "Interface to test with")
	flag.Parse()
	testInterface(*interfaceName)
}

func testInterface(interfaceName string) {
	config := tls.Config{ServerName: TEST_SERVER_HOST}

	var dialer net.Dialer
	netInterface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}
	addrs, err := netInterface.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	var selectedIP net.IP

	fmt.Println("Available IPs:")
	for i := 0; i < len(addrs); i++ {
		ip := addrs[i].(*net.IPNet).IP
		if ip.String() == interfaceName {
			selectedIP = ip
		}
		fmt.Println(ip.String())
	}
	if selectedIP == nil {
		fmt.Println("Did not find IP")
		return
	}

	tcpAddr := &net.TCPAddr{
		IP: selectedIP,
	}
	dialer = net.Dialer{
		LocalAddr: tcpAddr,
		Timeout:   5 * time.Second,
	}

	conn, err := tls.DialWithDialer(&dialer, TEST_SERVER_TYPE, TEST_SERVER_HOST+":"+TEST_SERVER_PORT, &config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + TEST_SERVER_HOST + "\r\nUser-Agent: curl/7.81.0\r\n\r\n"))

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			fmt.Println("EOF")
			break
		}
		if err != nil {
			fmt.Println("Error reading:", err)
			return
		}
		fmt.Println(string(buf[:n]))
	}
}

package utils

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"crypto/tls"

	"github.com/google/uuid"
)

type KikConnectionInfo struct {
	CerificateHost string

	Host *string
	Port *string

	MinTlsVersion *uint16
	MaxTlsVersion *uint16

	Connections     map[string]net.Conn
	ConnectionMutex *sync.Mutex
}

const (
	_DEFAULT_KIK_HOST = "talk1600ip.kik.com"
)

func NewConnectionInfo() *KikConnectionInfo {
	return &KikConnectionInfo{
		// This should never change, it is used to verify the certificate of the server.
		// In cases when the host is changed to a random IP,
		// this will continue to verify that the owner of the IP
		// has a valid certificate for *.kik.com.
		CerificateHost: _DEFAULT_KIK_HOST,

		// XMPP host to connect to
		Host: strPointer(_DEFAULT_KIK_HOST),
		// You can use port 443 or 5223 here
		Port: strPointer("443"),

		MinTlsVersion: intPointer(tls.VersionTLS12),
		MaxTlsVersion: intPointer(tls.VersionTLS13),

		// Holds the list of active connections.
		Connections:     make(map[string]net.Conn),
		ConnectionMutex: &sync.Mutex{},
	}
}

func (c *KikConnectionInfo) AddConnection(conn net.Conn) string {
	c.ConnectionMutex.Lock()
	defer c.ConnectionMutex.Unlock()
	connId := uuid.New().String()
	c.Connections[connId] = conn
	return connId
}

func (c *KikConnectionInfo) RemoveConnection(connId string) {
	c.ConnectionMutex.Lock()
	defer c.ConnectionMutex.Unlock()
	conn, ok := c.Connections[connId]
	if ok {
		conn.Close()
		delete(c.Connections, connId)
	}
}

func (c *KikConnectionInfo) RemoveAllConnectionsByIp(ip string) {
	c.ConnectionMutex.Lock()
	defer c.ConnectionMutex.Unlock()
	for connId, conn := range c.Connections {
		connIp, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err == nil && ip == connIp {
			conn.Close()
			delete(c.Connections, connId)
		}
	}
}

func (c *KikConnectionInfo) RemoveAllConnections() {
	c.ConnectionMutex.Lock()
	defer c.ConnectionMutex.Unlock()
	for connId, conn := range c.Connections {
		conn.Close()
		delete(c.Connections, connId)
	}
}

func (c *KikConnectionInfo) MonitorServerHealth() {
	if runtime.GOOS == "windows" {
		// Not supported on Windows
		return
	}

	dnsResolver := makeDnsResolver()

	time.Sleep(5 * time.Second)
	for {
		idle0, total0, err := getCPUSample()
		if err != nil {
			log.Println("failed to read cpu info, not making any more attempts")
			return
		}
		time.Sleep(20 * time.Second)
		idle1, total1, err := getCPUSample()
		if err != nil {
			log.Println("failed to read cpu info, not making any more attempts")
			return
		}

		var idleTicks float64 = float64(idle1 - idle0)
		var totalTicks float64 = float64(total1 - total0)
		var cpuUsage float64 = 100 * (totalTicks - idleTicks) / totalTicks

		if cpuUsage >= 75 {
			log.Printf("CPU usage is %f%% [busy: %f, total: %f]\n", cpuUsage, totalTicks-idleTicks, totalTicks)

			// Rotate the IP address and port
			addrs, err := dnsResolver.LookupHost(context.Background(), _DEFAULT_KIK_HOST)
			if err != nil {
				log.Println("DNS lookup failed, can't rotate host: ", err)
				continue
			}
			if len(addrs) == 0 {
				log.Println("No A records returned for host " + _DEFAULT_KIK_HOST)
				continue
			}

			var newHost *string
			var newPort *string
			var newMinTlsVersion *uint16
			var newMaxTlsVersion *uint16

			if getRandomBool() {
				newPort = strPointer("5223")
			} else {
				newPort = strPointer("443")
			}

			if getRandomBool() {
				newMinTlsVersion = intPointer(tls.VersionTLS12)
				newMaxTlsVersion = intPointer(tls.VersionTLS12)
			} else {
				newMinTlsVersion = intPointer(tls.VersionTLS13)
				newMaxTlsVersion = intPointer(tls.VersionTLS13)
			}

			if len(addrs) == 1 {
				newHost = &addrs[0]
			} else {
				for {
					host := addrs[getRandomByte()%len(addrs)]
					if host != *c.Host {
						newHost = &host
						break
					}
				}
			}

			c.Host = newHost
			c.Port = newPort
			c.MinTlsVersion = newMinTlsVersion
			c.MaxTlsVersion = newMaxTlsVersion

			log.Printf("Selected new host: %s:%s (TLSv1.%d)\n", *newHost, *newPort, 774-*newMaxTlsVersion)
			c.RemoveAllConnections()
		}
	}
}

// https://stackoverflow.com/a/17783687
func getCPUSample() (idle uint64, total uint64, err error) {
	contents, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if fields[0] == "cpu" {
			numFields := len(fields)
			for i := 1; i < numFields; i++ {
				val, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					fmt.Println("Error: ", i, fields[i], err)
					continue
				}
				total += val // tally up all the numbers to get total ticks
				if i == 4 {  // idle is the 5th field in the cpu line
					idle = val
				}
			}
			return
		}
	}
	return
}

func makeDnsResolver() net.Resolver {
	return net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: time.Duration(8) * time.Second}
			return dialer.DialContext(ctx, network, "8.8.8.8:53") // Google DNS
		},
	}
}

func getRandomBool() bool {
	return getRandomByte()%2 == 0
}

func getRandomByte() int {
	b := []byte{0}
	if _, err := rand.Reader.Read(b); err != nil {
		panic(err)
	}
	return int(b[0])
}

func strPointer(s string) *string {
	return &s
}

func intPointer(i uint16) *uint16 {
	return &i
}

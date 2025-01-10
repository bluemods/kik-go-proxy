package utils

import (
	"log"
	"net"
	"reflect"
)

// Extracts the IP address from a net.Conn,
// returns "<nil>" if unavailable.
func ConnToIp(conn net.Conn) string {
	switch addr := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		return addr.IP.String()
	case *net.UDPAddr:
		return addr.IP.String()
	default:
		log.Printf("ConnToIp: unknown RemoteAddr type '%s'", reflect.TypeOf(addr).Name())
		return "<nil>"
	}
}

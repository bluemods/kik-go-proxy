package server

import (
	"net"
	"sync"
	"sync/atomic"
)

var (
	// uint32 has 4.2B limit,
	// I don't think we will be serving that many connections
	currentConnId = &atomic.Uint32{}
)

type KikConnectionHolder struct {
	// Holds the list of active connections.
	connections map[uint32]net.Conn
	mutex       *sync.Mutex
}

func NewConnectionHolder() *KikConnectionHolder {
	return &KikConnectionHolder{
		connections: make(map[uint32]net.Conn),
		mutex:       &sync.Mutex{},
	}
}

// Disconnects all clients under a given IP address.
func (c *KikConnectionHolder) DisconnectIp(ip string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for connId, conn := range c.connections {
		connIp, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err == nil && ip == connIp {
			conn.Close()
			delete(c.connections, connId)
		}
	}
}

// Disconnects all clients
func (c *KikConnectionHolder) DisconnectAll() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for connId, conn := range c.connections {
		conn.Close()
		delete(c.connections, connId)
	}
}

func (c *KikConnectionHolder) onConnected(conn net.Conn) uint32 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	connId := currentConnId.Add(1)
	c.connections[connId] = conn
	return connId
}

func (c *KikConnectionHolder) onDisconnected(connId uint32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	conn, ok := c.connections[connId]
	if ok {
		conn.Close()
		delete(c.connections, connId)
	}
}

package server

import (
	"net"
	"sync"

	"github.com/google/uuid"
)

// I'm struggling to think of a better name. Suggest me one.
type KikConnectionHolder struct {
	// Holds the list of active connections.
	connections map[string]net.Conn
	mutex       *sync.Mutex
}

func NewConnectionHolder() *KikConnectionHolder {
	return &KikConnectionHolder{
		connections: make(map[string]net.Conn),
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

func (c *KikConnectionHolder) onConnected(conn net.Conn) string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	connId := uuid.New().String()
	c.connections[connId] = conn
	return connId
}

func (c *KikConnectionHolder) onDisconnected(connId string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	conn, ok := c.connections[connId]
	if ok {
		conn.Close()
		delete(c.connections, connId)
	}
}

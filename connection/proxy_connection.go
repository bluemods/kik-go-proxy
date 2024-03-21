package connection

import (
	"errors"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bluemods/kik-go-proxy/constants"
	"github.com/bluemods/kik-go-proxy/node"
	"github.com/bluemods/kik-go-proxy/ratelimit"
)

type KikProxyConnection struct {
	UserId   string
	IsAuthed bool

	ClientConn  net.Conn
	ClientInput node.NodeInputStream

	KikConn  net.Conn
	KikInput node.NodeInputStream

	RateLimiter *ratelimit.KikRateLimiter

	IsConnected atomic.Bool

	Logger *XmppLogger
}

// This routine blocks until the connection is finished.
func (c *KikProxyConnection) Run() {
	wg := sync.WaitGroup{}
	wg.Add(1)

	c.IsConnected.Store(true)
	c.ClientConn.SetDeadline(time.Time{})
	c.KikConn.SetDeadline(time.Time{})

	go func() {
		defer wg.Done()
		c.clientThread()
	}()
	c.kikThread()
	wg.Wait() // Wait for client thread to finish
}

// Processes incoming stanzas from the client and forwards them to Kik.
func (c *KikProxyConnection) clientThread() {
	isClientThread := true
	readConn := c.ClientConn
	input := c.ClientInput
	writeConn := c.KikConn

	defer c.onThreadFinished(isClientThread, input)()

	for c.IsConnected.Load() {
		readConn.SetReadDeadline(time.Now().Add(constants.CLIENT_READ_TIMEOUT_SECONDS * time.Second))
		_, stanza, err := input.ReadNextStanza()

		if err != nil {
			c.handleReadError(err, input, writeConn)
			return
		}
		if c.Logger != nil {
			c.Logger.OnNewStanza(*stanza, true)
		}

		writeConn.SetWriteDeadline(time.Now().Add(constants.WRITE_TIMEOUT_SECONDS * time.Second))
		if _, err = writeConn.Write(*stanza); err != nil {
			c.handleWriteError(err, *stanza, isClientThread)
			return
		}
	}
}

// Processes incoming stanzas from Kik and forwards them to the client.
func (c *KikProxyConnection) kikThread() {
	isClientThread := false
	readConn := c.KikConn
	input := c.KikInput
	writeConn := c.ClientConn
	rateLimiter := c.RateLimiter

	defer c.onThreadFinished(isClientThread, input)()

	for c.IsConnected.Load() {
		readConn.SetReadDeadline(time.Now().Add(constants.CLIENT_READ_TIMEOUT_SECONDS * time.Second))
		node, stanza, err := input.ReadNextStanza()

		if err != nil {
			c.handleReadError(err, input, writeConn)
			return
		}
		if c.Logger != nil {
			c.Logger.OnNewStanza(*stanza, false)
		}

		if rateLimiter != nil && rateLimiter.ProcessMessage(readConn, *node) {
			continue
		}

		writeConn.SetWriteDeadline(time.Now().Add(constants.WRITE_TIMEOUT_SECONDS * time.Second))
		if _, err = writeConn.Write(*stanza); err != nil {
			c.handleWriteError(err, *stanza, isClientThread)
			return
		}
	}
}

func (c *KikProxyConnection) onThreadFinished(isClientThread bool, input node.NodeInputStream) func() {
	return func() {
		if r := recover(); r != nil {
			log.Printf("ProxyConnection panic (isClientThread=%t, userId=%s, buf=%s)\n%s\n",
				isClientThread,
				c.UserId,
				input.Reader.GetBuffer(),
				r,
			)
			debug.PrintStack()
		}
		if c.IsConnected.CompareAndSwap(true, false) {
			// One of the threads finished, ensure both promptly close
			c.KikConn.Close()
			c.ClientConn.Close()
		}
	}
}

func (conn *KikProxyConnection) handleReadError(err error, input node.NodeInputStream, output net.Conn) {
	errMessage := err.Error()

	if strings.HasPrefix(errMessage, "XML syntax error") {
		if strings.HasSuffix(errMessage, "unexpected end element </k>") || strings.HasSuffix(errMessage, "unexpected EOF") {
			// XML parser currently treats it like an error.
			// Send it manually to properly close connection.
			// Very short timeout since the connection is about to be closed anyway.
			output.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			output.Write([]byte("</k>"))
		} else {
			// Log unexpected XML parsing errors
			log.Printf("Unexpected XML parsing error:\n%s\nStanza:\n%x\n",
				err.Error(), input.Reader.GetBuffer())
		}
	}
}

func (conn *KikProxyConnection) handleWriteError(err error, stanza []byte, isClientThread bool) {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		log.Printf("Write deadline exceeded. packetSize=%d, isClient=%t\n",
			len(stanza), isClientThread)
	}
}

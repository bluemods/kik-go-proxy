package plugins

import (
	"crypto/tls"
	"net"

	"github.com/bluemods/kik-go-proxy/node"
)

// The implementation for this interface is not publicly provided.
// To implement this interface, do the following:
//
// - Create a go file in the current directory
//
// - Add the following code:
//
//	 package node
//
//	 type ProxyInterceptorImpl struct {}
//
//	 // implement all funcs here...
//
//	 // init is a special method that is automatically called by the runtime
//	 func init() {
//		Transformer = &ProxyInterceptor{}
//	 }
type ProxyInterceptor interface {
	// Dials the XMPP server using the InitialStreamTag from the client as context.
	// Here you can use a custom domain, chain proxies, etc.
	// You should not read from or write to the socket, the server handles this already.
	Dial(k *node.InitialStreamTag, dialer *net.Dialer, network string, addr string, config *tls.Config) (*tls.Conn, error)

	// Transforms a stream init tag.
	MakeStreamInitTag(k *node.InitialStreamTag) string
}

var (
	// Will be nil when not implemented
	Interceptor ProxyInterceptor
)

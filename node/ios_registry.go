package node

import "crypto/tls"

// The implementation for this interface is not publicly provided.
// To implement this interface, do the following:
//
// - Create a go file in the current directory
//
// - Add the following code:
//
//	 package node
//
//	 type IosPacketTransformerImpl struct {
//		IosPacketTransformer
//	 }
//
//	 // implement all funcs here...
//
//	 // init is a special method that is automatically called by the runtime
//	 func init() {
//		Transformer = &IosPacketTransformerImpl{}
//	 }
type IosPacketTransformer interface {
	// Dials the XMPP server using the InitialStreamTag from the client as context.
	// Here you can use a custom domain, chain proxies, etc.
	// You should not read from or write to the socket, the server handles this already.
	Dial(InitialStreamTag) (*tls.Conn, error)

	// Transforms a stream init tag to iOS format.
	MakeStreamInitTag(InitialStreamTag) string

	// Translates a login request to iOS format.
	// MakeLoginXml() string

	// Translates a sign up request to iOS format.
	// MakeSignUpXml() string

	// Translates an outgoing message stanza to iOS format.
	// TransformMessageStanza() string
}

var (
	// Will be nil when not implemented
	IosTransformer IosPacketTransformer
)

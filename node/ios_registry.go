package node

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
	// Transforms a stream init tag to iOS format.
	MakeStreamInitTag(InitialStreamTag) string

	// Translates a login request to iOS format.
	// MakeLoginXml() string

	// Translates a sign up request to iOS format.
	// MakeSignUpXml() string
}

var (
	// Will be nil when not implemented
	IosTransformer IosPacketTransformer
)

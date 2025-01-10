package node

import (
	"bytes"
	"errors"
	"io"

	xpp "github.com/bluemods/kik-go-proxy/third_party/goxpp"
)

type NodeInputStream struct {
	Reader LoggingReader
	Parser xpp.XMLPullParser
}

// Read the next stanza from the input stream.
//
// If an error is encountered, node and string will be nil.
//
// If successful, the node object and the raw stanza
// will be returned in the first two values.
func (input NodeInputStream) ReadNextStanza() (node *Node, xml []byte, err error) {
	parser := input.Parser
	for {
		event, err := parser.Next()
		if err != nil {
			return nil, nil, err
		}
		if event == xpp.StartTag {
			node, err := ParseNextNode(&parser)
			if err != nil {
				return nil, nil, err
			}
			buffer := input.Reader.GetBuffer()
			return node, buffer, nil
		} else if event == xpp.EndTag && (parser.Name == "k" || parser.Name == "stream:stream") {
			return nil, nil, errors.New("end of stream reached: " + parser.Name)
		} else if event == xpp.EndDocument {
			return nil, nil, errors.New("end of stream reached")
		}
	}
}

// Reads the next IQ stanza.
func (input NodeInputStream) ReadNextIq() (node *Node, xml []byte, err error) {
	for {
		node, stanza, err := input.ReadNextStanza()
		if err != nil || node.Name == "iq" {
			return node, stanza, err
		}
	}
}

// Create a XMLPullParser for a long-lived input stream.
func NewNodeInputStream(ioReader io.Reader) NodeInputStream {
	reader := &ByteBufferLoggingReader{
		r:   ioReader,
		buf: new(bytes.Buffer),
	}
	cr := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	return NodeInputStream{
		Reader: reader,
		Parser: *xpp.NewXMLPullParser(reader, false, cr),
	}
}

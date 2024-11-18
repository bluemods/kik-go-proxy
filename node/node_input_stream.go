package node

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"

	xpp "github.com/bluemods/kik-go-proxy/third_party/goxpp"
)

type NodeInputStream struct {
	Reader *LoggingBufferedReader
	Parser xpp.XMLPullParser
}

// Read the next stanza from the input stream.
//
// If an error is encountered, node and string will be nil.
//
// If successful, the node object and the raw stanza
// will be returned in the first two values.
func (input NodeInputStream) ReadNextStanza() (node *Node, xml *[]byte, err error) {
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
			return node, &buffer, nil
		} else if event == xpp.EndTag && (parser.Name == "k" || parser.Name == "stream:stream") {
			return nil, nil, errors.New("end of stream reached: " + parser.Name)
		} else if event == xpp.EndDocument {
			return nil, nil, errors.New("end of stream reached")
		}
	}
}

// Create a XMLPullParser for a long-lived input stream.
func NewNodeInputStream(connection net.Conn) NodeInputStream {
	reader := &LoggingBufferedReader{
		r:   bufio.NewReader(connection),
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

// Sits on top of the real reader so we can log the raw XMPP
type LoggingBufferedReader struct {
	r   io.Reader
	buf *bytes.Buffer
}

func (r *LoggingBufferedReader) Read(p []byte) (n int, err error) {
	nRead, nError := r.r.Read(p)
	if nRead > 0 {
		r.buf.Write(p[0:nRead])
	}
	return nRead, nError
}

func (r *LoggingBufferedReader) GetBuffer() []byte {
	buffer := r.buf.Bytes()
	r.ClearBuffer()
	return buffer
}

func (r *LoggingBufferedReader) ClearBuffer() {
	r.buf.Reset()

	// Recreate buf if the previous stanza read was large in size.
	// Without this, the unused large buffer remains in
	// memory for the lifetime of the stream and may not be GCed for hours.
	// This way, it is quickly freed, at the cost of slightly increased CPU effort
	// due to more grow() calls being required.
	if r.buf.Cap() >= 4096 {
		r.buf = new(bytes.Buffer)
	}
}

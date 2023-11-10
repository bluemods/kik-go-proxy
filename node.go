package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"

	xpp "github.com/mmcdole/goxpp"
)

type Node struct {
	Attributes map[string]string
	Children   []Node
	Name       string
	Text       string
}

// Reads the next Node from the XMLPull Parser.
// Parser must be positioned on a StartTag.
func ParseNextNode(parser *xpp.XMLPullParser) (*Node, error) {
	if parser.Event != xpp.StartTag {
		return nil, errors.New("Expected start tag")
	}
	var ret = new(Node)
	ret.Text = ""
	ret.Name = parser.Name
	ret.Attributes = map[string]string{}
	for _, attr := range parser.Attrs {
		ret.Attributes[attr.Name.Local] = attr.Value
	}

	for {
		eventType, err := parser.Next()
		if err != nil {
			return nil, err
		} else if eventType == xpp.StartTag {
			child, err := ParseNextNode(parser)
			if err != nil {
				return nil, err
			}
			ret.Children = append(ret.Children, *child)
		} else if eventType == xpp.Text {
			ret.Text = parser.Text
		} else if eventType == xpp.EndTag || eventType == xpp.EndDocument {
			return ret, nil
		}
	}
}

func ParseInitialK(parser *xpp.XMLPullParser) (*Node, error) {
	if parser.Event != xpp.StartTag {
		return nil, errors.New("Expected start tag")
	}
	if parser.Name != "k" {
		return nil, errors.New("Expected k tag")
	}
	var ret = new(Node)
	ret.Text = ""
	ret.Name = parser.Name
	ret.Attributes = map[string]string{}
	for _, attr := range parser.Attrs {
		ret.Attributes[attr.Name.Local] = attr.Value
	}
	first := true

	for {
		eventType, err := parser.Next()
		if err != nil {
			if first && err == io.EOF {
				// Stream headers can be unclosed,
				// this is normal. Return the node.
				return ret, nil
			} else {
				return nil, err
			}
		} else if eventType == xpp.StartTag {
			child, err := ParseNextNode(parser)
			if err != nil {
				return nil, err
			}
			ret.Children = append(ret.Children, *child)
		} else if eventType == xpp.Text {
			ret.Text = parser.Text
		} else if eventType == xpp.EndTag || eventType == xpp.EndDocument {
			return ret, nil
		}
		first = false
	}
}

// Parse a <k/> string.
// They need special handling as they are not always closed.
func ParseInitialKString(xmpp string) (*Node, error) {
	reader := strings.NewReader(xmpp)
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	parser.Next()
	return ParseInitialK(parser)
}

// Parse an XMPP string
// Note that this will return an error if all tags are not properly closed.
func ParseXmppString(xmpp string) (*Node, error) {
	reader := strings.NewReader(xmpp)
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	parser.Next()
	return ParseNextNode(parser)
}

// Sits on top of the real reader so we can log the raw XMPP
type LoggingBufferedReader struct {
	r      io.Reader
	Buffer *strings.Builder
}

func (r LoggingBufferedReader) Read(p []byte) (n int, err error) {
	nRead, nError := r.r.Read(p)
	if nRead > 0 {
		r.Buffer.Write(p[0:nRead])
	}
	return nRead, nError
}

func (r LoggingBufferedReader) GetBuffer() string {
	buffer := r.Buffer.String()
	r.ClearBuffer()
	return buffer
}

func (r LoggingBufferedReader) ClearBuffer() {
	r.Buffer.Reset()
}

type NodeInputStream struct {
	Reader LoggingBufferedReader
	Parser xpp.XMLPullParser
}

// Read the next stanza from the input stream.
//
// If an error is encountered, node and string will be nil.
//
// If successful, the node object and the raw stanza
// will be returned in the first two values.
func (input NodeInputStream) ReadNextStanza() (*Node, *string, error) {
	parser := input.Parser
	for {
		eventType, err := parser.Next()
		if err != nil {
			return nil, nil, err
		}
		if eventType == xpp.EndTag || eventType == xpp.EndDocument {
			name := parser.Name
			if eventType == xpp.EndDocument || name == "k" || name == "stream:stream" {
				return nil, nil, errors.New("End of stream reached: '" + name + "'")
			}
		}
		if eventType == xpp.StartTag {
			node, err := ParseNextNode(&parser)
			if err != nil {
				return nil, nil, err
			}
			buffer := input.Reader.GetBuffer()
			return node, &buffer, nil
		}
	}
}

// Create a XMLPullParser for a long-lived input stream.
func CreateNodeInputStream(connection net.Conn) NodeInputStream {
	realReader := bufio.NewReader(connection)
	loggingReader := LoggingBufferedReader{
		r:      realReader,
		Buffer: new(strings.Builder),
	}
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	return NodeInputStream{
		Reader: loggingReader,
		Parser: *xpp.NewXMLPullParser(loggingReader, false, crReader),
	}
}

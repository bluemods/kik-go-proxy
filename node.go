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

func parse(parser *xpp.XMLPullParser) (*Node, error) {
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
			child, err := parse(parser)
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

/*
Parse an XMPP string
Since initial k tags are not always closed (as they are a stream header)
we must manually close them to make the parser work.

This limitation may be revisited later.
*/
func parseInitialKString(xmpp string) (*Node, error) {
	fixed := strings.Trim(strings.TrimSuffix(xmpp, "</k>"), " ") + "</k>"
	if !strings.HasPrefix(fixed, "<k ") {
		return nil, errors.New("Not a valid k tag\n" + xmpp)
	}
	return parseXmppString(fixed)
}

/*
Parse an XMPP string
Note that this will return an error if all tags are not properly closed.
*/
func parseXmppString(xmpp string) (*Node, error) {
	reader := strings.NewReader(xmpp)
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	parser.Next()
	return parse(parser)
}

/*
Sits on top of the real reader so we can log the raw XMPP
*/
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

/*
Read the next stanza from the input stream.

If an error is encountered, node and string will be nil.

If successful, the node object and the raw stanza
will be returned in the first two values.
*/
func (input NodeInputStream) readNextStanza() (*Node, *string, error) {
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
			node, err := parse(&parser)
			if err != nil {
				return nil, nil, err
			}
			buffer := input.Reader.GetBuffer()
			return node, &buffer, nil
		}
	}
}

/*
Create a XMLPullParser for a long-lived input stream.
*/
func createParser(connection net.Conn) NodeInputStream {
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

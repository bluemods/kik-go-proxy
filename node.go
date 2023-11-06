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
Create a XMLPullParser for a long-lived input stream.
*/
func createParser(connection net.Conn) *xpp.XMLPullParser {
	reader := bufio.NewReader(connection)
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	return xpp.NewXMLPullParser(reader, false, crReader)
}

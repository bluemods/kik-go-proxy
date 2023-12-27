package node

import (
	"errors"
	"io"
	"strings"

	xpp "github.com/mmcdole/goxpp"
)

// Reads the next Node from the XMLPull Parser.
// Parser must be positioned on a StartTag.
func ParseNextNode(parser *xpp.XMLPullParser) (*Node, error) {
	if parser.Event != xpp.StartTag {
		return nil, errors.New("expected start tag")
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
		return nil, errors.New("expected start tag")
	}
	if parser.Name != "k" {
		return nil, errors.New("expected k tag")
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
			if first && strings.HasSuffix(err.Error(), "unexpected EOF") {
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
	reader := strings.NewReader(strings.Trim(xmpp, " "))
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
	reader := strings.NewReader(strings.Trim(xmpp, " "))
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	parser.Next()
	return ParseNextNode(parser)
}

package node

import (
	"errors"
	"io"
	"strings"

	xpp "github.com/bluemods/kik-go-proxy/goxpp"
)

type Node struct {
	Attributes map[string]string
	Children   []Node
	Name       string
	Text       string
}

// Returns true if the Node contains the attribute key.
func (n Node) HasAttribute(key string) bool {
	_, found := n.Attributes[key]
	return found
}

// Returns true if there is a child with the same name as the parameter.
func (n Node) HasTag(name string) bool {
	return n.Find(name) != nil
}

// Finds an attribute value by its name.
// Returns an empty string if not found.
func (n Node) Get(key string) string {
	ret, found := n.Attributes[key]
	if found {
		return ret
	} else {
		return ""
	}
}

// Finds the first matching child by its name.
// Returns nil if not found.
func (n Node) Find(name string) *Node {
	for _, child := range n.Children {
		if child.Name == name {
			return &child
		}
	}
	return nil
}

// Finds the last matching child by its name.
// Returns nil if not found.
func (n Node) FindLast(name string) *Node {
	for i := len(n.Children) - 1; i >= 0; i-- {
		child := n.Children[i]
		if child.Name == name {
			return &child
		}
	}
	return nil
}

// Finds all matching children by name.
func (n Node) FindAll(name string) (ret []Node) {
	for _, child := range n.Children {
		if child.Name == name {
			ret = append(ret, child)
		}
	}
	return ret
}

// Reads the next Node from the XMLPull Parser.
// Parser must be positioned on a StartTag.
func ParseNextNode(parser *xpp.XMLPullParser) (*Node, error) {
	if parser.Event != xpp.StartTag {
		return nil, errors.New("expected start tag")
	}
	node := new(Node)
	node.Text = ""
	node.Name = parser.Name
	node.Attributes = map[string]string{}
	for _, attr := range parser.Attrs {
		node.Attributes[attr.Name.Local] = attr.Value
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
			node.Children = append(node.Children, *child)
		} else if eventType == xpp.Text {
			node.Text = parser.Text
		} else if eventType == xpp.EndTag {
			return node, nil
		} else if eventType == xpp.EndDocument {
			return nil, errors.New("unexpected end of document before end of stanza")
		}
	}
}

// Parses an initial stream header from a string.
// Stream headers must not be self-closing.
func ParseStreamHeader(xmpp string) (*Node, error) {
	parser, err := NewStringPullParser(xmpp)
	if err != nil {
		return nil, err
	}
	if parser.Event != xpp.StartTag {
		return nil, errors.New("expected start tag")
	}
	if parser.Name != "k" {
		return nil, errors.New("expected k tag")
	}
	node := new(Node)
	node.Text = ""
	node.Name = parser.Name
	node.Attributes = map[string]string{}
	for _, attr := range parser.Attrs {
		node.Attributes[attr.Name.Local] = attr.Value
	}
	return node, nil
}

// Parse an XMPP string
// Note that this will return an error if all tags are not properly closed.
func ParseXmppString(xmpp string) (*Node, error) {
	parser, err := NewStringPullParser(xmpp)
	if err != nil {
		return nil, err
	}
	return ParseNextNode(parser)
}

// Creates a new XMLPullParser for a given string.
func NewStringPullParser(xmpp string) (*xpp.XMLPullParser, error) {
	reader := strings.NewReader(strings.Trim(xmpp, " "))
	crReader := func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	parser := xpp.NewXMLPullParser(reader, false, crReader)
	_, err := parser.Next()
	return parser, err
}

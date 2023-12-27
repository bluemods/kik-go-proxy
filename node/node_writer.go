package node

import (
	"bytes"

	"github.com/shabbyrobe/xmlwriter"
)

// Simplifies stanza creation.
type NodeWriter struct {
	_buf *bytes.Buffer
	_w   *xmlwriter.Writer
}

func NewNodeWriter() NodeWriter {
	buf := new(bytes.Buffer)
	w := xmlwriter.Open(buf)
	return NodeWriter{_buf: buf, _w: w}
}

func (w NodeWriter) StartTag(name string) NodeWriter {
	w._w.StartElem(xmlwriter.Elem{Name: name})
	return w
}

func (w NodeWriter) EndTag(name string) NodeWriter {
	w._w.EndElem(name)
	return w
}

func (w NodeWriter) Attribute(name string, value string) NodeWriter {
	w._w.WriteAttr(xmlwriter.Attr{Name: name, Value: value})
	return w
}

func (w NodeWriter) AttributeIf(name string, value *string) NodeWriter {
	if value != nil {
		w._w.WriteAttr(xmlwriter.Attr{Name: name, Value: *value})
	}
	return w
}

func (w NodeWriter) TagText(name string, value string) NodeWriter {
	w.StartTag(name)
	w.Text(value)
	w.EndTag(name)
	return w
}

func (w NodeWriter) TagTextIf(name string, value *string) NodeWriter {
	if value != nil {
		w.StartTag(name)
		w.Text(*value)
		w.EndTag(name)
	}
	return w
}

func (w NodeWriter) Text(text string) NodeWriter {
	w._w.WriteText(text)
	return w
}

func (w NodeWriter) String() string {
	w._w.EndAllFlush()
	return w._buf.String()
}
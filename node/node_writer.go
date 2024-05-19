package node

import (
	"bytes"

	xmlwriter "github.com/bluemods/kik-go-proxy/third_party/xmlwriter"
)

// Simplifies stanza creation.
type NodeWriter struct {
	_buf *bytes.Buffer
	_w   *xmlwriter.Writer
	_err *xmlwriter.ErrCollector
}

func NewNodeWriter() NodeWriter {
	buf := new(bytes.Buffer)
	w := xmlwriter.Open(buf)
	err := &xmlwriter.ErrCollector{}
	return NodeWriter{
		_buf: buf,
		_w:   w,
		_err: err,
	}
}

// Begins a tag.
func (w NodeWriter) StartTag(name string) NodeWriter {
	w._w.StartElem(xmlwriter.Elem{Name: name})
	return w
}

// Ends a tag that was previously opened via StartTag.
func (w NodeWriter) EndTag(name string) NodeWriter {
	w._w.EndElem(name)
	return w
}

// Writes an attribute.
// Writer must be positioned on a StartTag.
func (w NodeWriter) Attribute(name string, value string) NodeWriter {
	w._w.WriteAttr(xmlwriter.Attr{Name: name, Value: value})
	return w
}

// Writes an attribute.
// Writer must be positioned on a StartTag.
// No-op if value is nil.
func (w NodeWriter) AttributeIf(name string, value *string) NodeWriter {
	if value != nil {
		w._w.WriteAttr(xmlwriter.Attr{Name: name, Value: *value})
	}
	return w
}

// Writes StartTag, then EndTag.
// Serialized as <foo></foo>
func (w NodeWriter) EmptyTag(name string) NodeWriter {
	w._w.StartElem(xmlwriter.Elem{Name: name, Full: true})
	w._w.EndElem(name)
	return w
}

// Writes StartTag, Text, then EndTag.
func (w NodeWriter) TagText(name string, value string) NodeWriter {
	w.StartTag(name)
	w.Text(value)
	w.EndTag(name)
	return w
}

// Writes StartTag, Text, then EndTag. Does nothing if value is nil.
func (w NodeWriter) TagTextIf(name string, value *string) NodeWriter {
	if value != nil {
		w.StartTag(name)
		w.Text(*value)
		w.EndTag(name)
	}
	return w
}

// Writes text. Caller must have called StartTag or Attribute prior to calling this.
func (w NodeWriter) Text(text string) NodeWriter {
	w._w.WriteText(text)
	return w
}

// Closes all open tags.
func (w NodeWriter) EndAllFlush() {
	w._w.EndAllFlush()
}

// Returns the serialized XML.
// This function panics if the xmlwriter encountered an error when writing,
// which occurs if the caller uses functions in a wrong order (i.e. end tag without start tag)
func (w NodeWriter) String() string {
	if err := w._w.Flush(); err != nil {
		panic(err)
	}
	w._err.Panic()
	return w._buf.String()
}

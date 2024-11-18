package node

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/bluemods/kik-go-proxy/third_party/xmlwriter"
)

// Simplifies stanza creation.
type NodeWriter struct {
	_buf     *bytes.Buffer
	_w       *xmlwriter.Writer
	_err     *xmlwriter.ErrCollector
	_iosMode bool
}

// Creates a new NodeWriter that writes in default (Android) style.
func NewNodeWriter() NodeWriter {
	buf := new(bytes.Buffer)
	w := xmlwriter.Open(buf)
	err := &xmlwriter.ErrCollector{}
	return NodeWriter{
		_buf:     buf,
		_w:       w,
		_err:     err,
		_iosMode: false,
	}
}

// Creates a new NodeWriter that writes in iOS style.
func NewIosWriter() NodeWriter {
	buf := new(bytes.Buffer)
	w := xmlwriter.Open(buf, xmlwriter.WithIosStyle())
	err := &xmlwriter.ErrCollector{}
	return NodeWriter{
		_buf:     buf,
		_w:       w,
		_err:     err,
		_iosMode: true,
	}
}

// Creates a new NodeWriter that pretty prints the XML as it writes events.
func NewIndentedNodeWriter() NodeWriter {
	buf := new(bytes.Buffer)
	w := xmlwriter.Open(buf, xmlwriter.WithIndent())
	err := &xmlwriter.ErrCollector{}
	return NodeWriter{
		_buf:     buf,
		_w:       w,
		_err:     err,
		_iosMode: false,
	}
}

// Begins (opens) a tag.
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

// Writes StartTag, empty text, then EndTag.
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

// Writes a <kik/> element, required for all outgoing message stanzas
func (w NodeWriter) WriteKikTag(push bool, qos bool, timestamp string) NodeWriter {
	w.StartTag("kik")
	w.Attribute("push", strconv.FormatBool(push))
	w.Attribute("qos", strconv.FormatBool(qos))
	w.Attribute("timestamp", timestamp)
	w.EndTag("kik")
	return w
}

// Writes a request element, required for outgoing messages containing user facing content
func (w NodeWriter) WriteRequestTag(requestDelivered bool, requestRead bool) NodeWriter {
	if !requestDelivered && !requestRead {
		return w
	}
	w.StartTag("request")
	w.Attribute("xmlns", "kik:message:receipt")
	w.Attribute("r", strconv.FormatBool(requestDelivered))
	w.Attribute("d", strconv.FormatBool(requestRead))
	w.EndTag("request")
	return w
}

// Writes text. Caller must have called StartTag or Attribute prior to calling this.
func (w NodeWriter) Text(text string) NodeWriter {
	sb := strings.Builder{}
	sb.Grow(len(text))

	// We only escape these 3 characters. This matches Kik's output style.
	for _, r := range text {
		switch r {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		default:
			sb.WriteRune(r)
		}
	}
	w._w.WriteRawText(sb.String())
	return w
}

// Closes all open tags.
func (w NodeWriter) EndAllFlush() {
	w._w.EndAllFlush()
}

// Writes the contents of a Node into the NodeWriter.
func (w NodeWriter) WriteNode(n Node) {
	w.StartTag(n.Name)
	for k, v := range n.Attributes {
		w.Attribute(k, v)
	}
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			w.WriteNode(child)
		}
	} else if len(n.Text) > 0 {
		w.Text(n.Text)
	}
	w.EndTag(n.Name)
}

// Writes a raw string, not escaped.
func (w NodeWriter) WriteRaw(xml string) NodeWriter {
	w._w.WriteRaw(xml)
	return w
}

// Returns true if the writer is currently in iOS style.
// When true, it can be assumed that the packet must emulate iOS output.
func (w NodeWriter) IsIos() bool {
	return w._iosMode
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

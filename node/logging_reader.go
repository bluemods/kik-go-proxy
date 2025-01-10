package node

import (
	"bytes"
	"io"
	"strings"
)

// An io.Reader that logs data that it reads into a byte buffer.
// Once a stanza is read, either GetBuffer or ClearBuffer must be called.
type LoggingReader interface {
	// Retrieves the buffer.
	// The buffer will be cleared once this call returns.
	GetBuffer() []byte

	// Clears the buffer, freeing the allocated memory.
	ClearBuffer()

	io.Reader
}

type ByteBufferLoggingReader struct {
	r   io.Reader
	buf *bytes.Buffer
}

func (r *ByteBufferLoggingReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if n > 0 {
		r.buf.Write(p[0:n])
	}
	return
}

func (r *ByteBufferLoggingReader) GetBuffer() []byte {
	buffer := r.buf.Bytes()
	r.ClearBuffer()
	return buffer
}

func (r *ByteBufferLoggingReader) ClearBuffer() {
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

type StringBuilderLoggingReader struct {
	r   io.Reader
	buf *strings.Builder
}

func (r *StringBuilderLoggingReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if n > 0 {
		r.buf.Write(p[0:n])
	}
	return
}

func (r *StringBuilderLoggingReader) GetBuffer() []byte {
	buffer := []byte(r.buf.String())
	r.ClearBuffer()
	return buffer
}

func (r *StringBuilderLoggingReader) ClearBuffer() {
	r.buf.Reset()

	// Recreate buf if the previous stanza read was large in size.
	// Without this, the unused large buffer remains in
	// memory for the lifetime of the stream and may not be GCed for hours.
	// This way, it is quickly freed, at the cost of slightly increased CPU effort
	// due to more grow() calls being required.
	if r.buf.Cap() >= 4096 {
		r.buf = new(strings.Builder)
	}
}

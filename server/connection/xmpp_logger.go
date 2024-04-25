package connection

import (
	"compress/gzip"
	"errors"
	"io"
	"log"
	"os"
)

var (
	writeFailed bool = false
	useGzip     bool = false
	gzipLevel   int  = 4 // 1-9

	errWriteFailed error = errors.New("logger shut down due to write failure")

	incomingTag []byte = []byte{'<', '=', '=', ' '}
	outgoingTag []byte = []byte{'=', '=', '>', ' '}
)

type XmppLogger struct {
	Writer io.WriteCloser
}

func NewXmppLogger(outputFile string) (*XmppLogger, error) {
	if writeFailed {
		return nil, errWriteFailed
	}
	f, err := os.Open(outputFile)
	if err != nil {
		return nil, err
	}

	if useGzip {
		g, err := gzip.NewWriterLevel(f, gzipLevel)
		if err != nil {
			return nil, err
		}
		return &XmppLogger{Writer: g}, nil
	} else {
		return &XmppLogger{Writer: f}, nil
	}
}

func (x XmppLogger) OnNewStanza(data []byte, isOutgoing bool) error {
	if writeFailed {
		return errWriteFailed
	}
	var err error
	if isOutgoing {
		err = x.doWrite(outgoingTag)
	} else {
		err = x.doWrite(incomingTag)
	}

	if err == nil {
		err = x.doWrite(data)
		if err == nil {
			err = x.doWrite([]byte{'\n'})
		}
	}

	if err != nil {
		// Writes typically fail due to disk space constraints.
		// After writes fail, do not attempt again.
		if !writeFailed {
			writeFailed = true
			log.Println("XmppLogger: write failed, no more logs will be written. Caused by: " + err.Error())
		}
	}
	return err
}

func (x XmppLogger) Close() error {
	return x.Writer.Close()
}

// It's annoying to do '_, err' everywhere
func (x XmppLogger) doWrite(data []byte) error {
	_, err := x.Writer.Write(data)
	return err
}

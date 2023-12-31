package node

import (
	"net"
	"strconv"
	"time"

	"github.com/bluemods/kik-go-proxy/crypto"
	xpp "github.com/mmcdole/goxpp"
)

// Describes a bind response from Kik
type KikInitialStreamResponse struct {
	// True if Kik returned success on bind
	IsOk bool

	// The timestamp of the Kik server, used to sync the local time of our server and connecting clients.
	// If the client is binding pre-auth (anon="1"), the timestamp will be 0 and should be ignored.
	Timestamp int64

	// The raw stanza received from Kik.
	RawStanza string
}

func (response KikInitialStreamResponse) GenerateServerResponse(customBanner bool) string {
	if !response.IsOk || !customBanner {
		return response.RawStanza
	}
	k := NewNodeWriter()
	k.StartTag("k")
	k.Attribute("ok", "1")
	if response.Timestamp > 0 {
		k.Attribute("ts", strconv.FormatInt(response.Timestamp, 10))
	}
	k.Attribute("server", "KikGoProxyServer")
	return k.String() + ">"
}

func ParseInitialStreamResponse(kikConn net.Conn) (*KikInitialStreamResponse, error) {
	input := NewNodeInputStream(kikConn)
	parser := input.Parser
	for {
		event, err := parser.Next()
		if err != nil {
			return nil, err
		}
		if event == xpp.StartTag && parser.Name == "k" {
			break
		}
	}

	var isOk bool = parser.Attribute("ok") == "1"
	var timestamp int64 = 0
	var stanza string

	if isOk {
		// Ok response, stream header does not close until the stream ends
		ts, _ := strconv.ParseInt(parser.Attribute("ts"), 10, 64)
		if ts > 0 {
			timestamp = ts
			crypto.SetServerTimeOffset(ts - time.Now().UnixMilli())
		}
		stanza = input.Reader.GetBuffer()
	} else {
		// Not ok, the tag will be self closing
		// TODO return specialized error codes
		_, xml, err := input.ReadNextStanza()
		if err != nil {
			return nil, err
		}
		stanza = *xml
	}
	return &KikInitialStreamResponse{
		IsOk:      isOk,
		Timestamp: timestamp,
		RawStanza: stanza}, nil
}

package node

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bluemods/kik-go-proxy/crypto"
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
	} else {
		var k strings.Builder
		k.Write([]byte(`<k ok="1"`))
		if response.Timestamp > 0 {
			k.Write([]byte(` ts="` + strconv.FormatInt(response.Timestamp, 10) + `"`))
		}
		k.Write([]byte(` server="KikGoProxyServer">`))
		return k.String()
	}
}

func ParseInitialStreamResponse(kikConn net.Conn) (*KikInitialStreamResponse, error) {
	var stanza strings.Builder
	buf := make([]byte, 1)
	isBindRejected := false

	for {
		_, err := kikConn.Read(buf)
		if err != nil {
			return nil, err
		}
		var c byte = buf[0]
		stanza.WriteByte(c)
		if c == '>' {
			if !isBindRejected && strings.Contains(stanza.String(), " ok=\"1\"") {
				// When ok="1" is sent, bind succeeded, and there are no child elements
				// (we are at the end of the header)
				break
			}
			isBindRejected = true
			if strings.Contains(stanza.String(), "</k>") {
				// Stream response is not ok, there will be child elements.
				// Read until the k tag is closed
				break
			}
		}
	}
	k, err := ParseInitialKString(stanza.String())
	if err != nil {
		return nil, err
	}

	var isOk bool = k.Attributes["ok"] == "1"

	if v, ok := k.Attributes["ts"]; ok {
		timestamp, _ := strconv.ParseInt(v, 10, 64)
		if timestamp > 0 {
			crypto.SetServerTimeOffset(timestamp - time.Now().UnixMilli())
		}
		return &KikInitialStreamResponse{
			IsOk:      isOk,
			Timestamp: timestamp,
			RawStanza: stanza.String()}, nil
	} else {
		return &KikInitialStreamResponse{
			IsOk:      isOk,
			Timestamp: 0,
			RawStanza: stanza.String()}, nil
	}
}

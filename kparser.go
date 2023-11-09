package main

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bluemods/kik-go-proxy/crypto"
)

// The device ID component is relaxed compared to Kik's regex
// Normally, it should be a random UUID with dashes omitted
var fullJidRegex *regexp.Regexp = regexp.MustCompile(`^([a-z0-9\\.\\_]{2,30})(_[a-z0-9]{3})?@(.*)/([A-Z]{3})(.{6,32})$`)
var deviceIdRegex *regexp.Regexp = regexp.MustCompile("^([A-Z]{3})(.{6,32})$")

type FullJid struct {
	LocalPart string
	Domain    string
	DeviceId  KikDeviceId
}

func (jid FullJid) GetIdentifier() string {
	return jid.LocalPart + "@" + jid.Domain
}

func ParseFullJid(jid string) (*FullJid, error) {
	var match [][]string = fullJidRegex.FindAllStringSubmatch(jid, -1)

	if len(match) != 1 || len(match[0]) != 6 {
		return nil, errors.New("Invalid JID " + jid)
	} else {
		return &FullJid{
			LocalPart: match[0][1] + match[0][2],
			Domain:    match[0][3],
			DeviceId: KikDeviceId{
				Prefix: match[0][4],
				Id:     match[0][5],
			},
		}, nil
	}
}

type KikDeviceId struct {
	// Describes the device type.
	// 3 characters long, e.g. 'CAN'
	Prefix string

	// The ID of the device.
	Id string
}

func ParseDeviceId(id string) (*KikDeviceId, error) {
	var match [][]string = deviceIdRegex.FindAllStringSubmatch(id, -1)

	if len(match) != 1 || len(match[0]) != 3 {
		return nil, errors.New("Invalid device ID " + id)
	} else {
		return &KikDeviceId{
			Prefix: match[0][1],
			Id:     match[0][2],
		}, nil
	}
}

// Initial stanza that goes out to Kik
type OutgoingKPayload struct {
	RawStanza   string
	InterfaceIp string
	ApiKey      string
}

// Initial stanza read from the client
type InitialStreamTag struct {
	// The attributes in the <k stanza
	Attributes map[string]string

	// The raw stanza provided from the client
	RawStanza string

	// True if the client is authenticating with Kik using credentials
	IsAuth bool

	// if IsAuth == true, this is not nil, otherwise it is nil
	Jid *FullJid

	// The device ID in use by the client, not nil
	DeviceId KikDeviceId
}

func (k InitialStreamTag) GetUserId() string {
	if k.IsAuth {
		return k.Jid.GetIdentifier()
	} else {
		return k.DeviceId.Prefix + k.DeviceId.Id
	}
}

/*
Verifies the integrity of the stanza.
if error returned is not nil, verification failed.
*/
func (k InitialStreamTag) makeOutgoingPayload() (*OutgoingKPayload, error) {
	expected := crypto.MakeKTag(k.Attributes)
	received := k.RawStanza
	if expected != received {
		err := errors.New(
			"initial stream tag failed verification\n" +
				"Expected: " + expected + "\nReceived: " + received)
		return nil, err
	}

	var iface string = ""
	var apiKey string = ""
	var needsTransform bool = false

	if v, ok := k.Attributes["x-interface"]; ok {
		delete(k.Attributes, "x-interface")
		iface = v
		needsTransform = true
	}
	if v, ok := k.Attributes["x-api-key"]; ok {
		delete(k.Attributes, "x-api-key")
		apiKey = v
		needsTransform = true
	}
	if needsTransform {
		expected = crypto.MakeKTag(k.Attributes)
	}
	return &OutgoingKPayload{
		RawStanza:   expected,
		InterfaceIp: iface,
		ApiKey:      apiKey,
	}, nil
}

func ParseInitialStreamTag(conn net.Conn) (*InitialStreamTag, error) {
	var startTagSeen bool = false
	var whitespaceCount int = 0
	var characterCount int = 0

	var stanza strings.Builder
	buf := make([]byte, 1)

	for {
		_, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		var c = buf[0]
		stanza.WriteByte(c)

		characterCount++
		if characterCount > 1024 {
			return nil, errors.New("Too many characters in stream init tag\n" + stanza.String())
		}

		if !startTagSeen {
			if c == '<' {
				startTagSeen = true
			} else if c != ' ' {
				return nil, errors.New("invalid character '" + string(c) + "' before tag start")
			} else {
				whitespaceCount++
				if whitespaceCount > 29 {
					return nil, errors.New("Too many whitespaces before tag start\n" + stanza.String())
				}
			}
		} else {
			if c == '>' {
				break
			} else if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '\'' || c == '"' ||
				c == '=' || c == ' ' ||
				c == '.' || c == '@' ||
				c == '/' || c == '_' ||
				c == '&' || c == ';' ||
				c == '-' || c == '+' || c == ':') {
				return nil, errors.New("invalid character '" + string(c) + "' in stream init tag\n" + stanza.String())
			}
		}
	}
	if strings.HasSuffix(stanza.String(), "/>") {
		return nil, errors.New("initial stream tag already closed\n" + stanza.String())
	}
	node, err := ParseInitialKString(stanza.String())
	if err != nil {
		return nil, err
	}

	var attributes map[string]string = node.Attributes

	if _, ok := attributes["anon"]; ok {
		// This is an anon connection (pre-auth)

		dev, ok := attributes["dev"]
		if !ok {
			return nil, errors.New("No dev attribute in anon stanza")
		}

		deviceId, err := ParseDeviceId(dev)
		if err != nil {
			return nil, err
		}

		return &InitialStreamTag{
			Attributes: attributes,
			RawStanza:  stanza.String(),
			IsAuth:     false,
			Jid:        nil,
			DeviceId:   *deviceId,
		}, nil
	} else {
		// This is an authorized connection (post-auth)

		from, ok := attributes["from"]
		if !ok {
			return nil, errors.New("No from attribute in auth stanza")
		}
		jid, err := ParseFullJid(from)
		if err != nil {
			return nil, err
		}
		return &InitialStreamTag{
			Attributes: attributes,
			RawStanza:  stanza.String(),
			IsAuth:     true,
			Jid:        jid,
			DeviceId:   jid.DeviceId,
		}, nil
	}
}

type KikInitialStreamResponse struct {
	// True if Kik returned success on bind
	IsOk bool
	// The timestamp of the Kik server, used to sync the local time of our server and connecting clients.
	// If the client is binding pre-auth (anon="1"), the timestamp will be 0 and should be ignored.
	Timestamp int64
	// The raw stanza received from Kik.
	RawStanza string
}

func (response KikInitialStreamResponse) GenerateServerResponse() string {
	if !response.IsOk || !CUSTOM_BANNER {
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

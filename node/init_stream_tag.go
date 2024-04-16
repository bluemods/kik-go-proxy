package node

import (
	"errors"
	"log"
	"net"
	"strings"

	"github.com/bluemods/kik-go-proxy/crypto"
	"github.com/bluemods/kik-go-proxy/datatypes"
	"github.com/bluemods/kik-go-proxy/utils"
)

var (
	_bannableOffenses = []string{
		"tls: client offered only unsupported versions:",
		"tls: first record does not look like a TLS handshake",
	}
)

// Describes a bind request from the client
type InitialStreamTag struct {
	// The attributes in the <k stanza
	Attributes map[string]string

	// The raw stanza received from the client
	RawStanza string

	// True if the client is authenticating with Kik using credentials
	IsAuth bool

	// if IsAuth == true, this is not nil, otherwise it is nil
	Jid *datatypes.FullJid

	// The device ID in use by the client, not nil
	DeviceId datatypes.KikDeviceId

	// Optional interface IP specified by the client
	InterfaceIp *string

	// Optional API key specified by the client
	ApiKey *string
}

// Returns a unique identifier for the connecting client.
// For authed connections, this is the JID
// For anon connections, this is the Device ID (with prefix)
func (k InitialStreamTag) GetUserId() string {
	if k.IsAuth {
		return k.Jid.GetIdentifier()
	} else {
		return k.DeviceId.Prefix + k.DeviceId.Id
	}
}

// Generates the stream init tag initally written to the outbound socket to Kik.
func (k InitialStreamTag) GenerateStreamInitTag(iosMode bool) string {
	if iosMode {
		if IosTransformer == nil {
			log.Println("iosMode specified but there is no implementation registered. Using client generated tag.")
			return k.RawStanza
		} else {
			return IosTransformer.MakeStreamInitTag(k)
		}
	}
	return k.RawStanza
}

// Parses and verifies the initial stream tag from the client.
// If the error returned is nil, the parsing succeeded,
// and the other return values must be ignored.
// Returns: InitialStreamTag, shouldBanIp, error
func ParseInitialStreamTag(conn net.Conn) (*InitialStreamTag, bool, error) {
	defer utils.TimeMethod("ParseInitialStreamTag")()

	var startTagSeen bool = false
	var whitespaceCount int = 0
	var characterCount int = 0

	var stanza strings.Builder
	buf := make([]byte, 1)

	for {
		_, err := conn.Read(buf)
		if err != nil {
			errMessage := err.Error()
			for _, offense := range _bannableOffenses {
				if strings.Contains(errMessage, offense) {
					return nil, true, err
				}
			}
			return nil, false, err
		}
		var c = buf[0]
		stanza.WriteByte(c)

		characterCount++
		if characterCount > 1024 {
			return nil, true, errors.New("Too many characters in stream init tag\n" + stanza.String())
		}

		if !startTagSeen {
			if c == '<' {
				startTagSeen = true
			} else if c != ' ' {
				return nil, true, errors.New("invalid character '" + string(c) + "' before tag start")
			} else {
				whitespaceCount++
				if whitespaceCount > 29 {
					return nil, true, errors.New("Too many whitespaces before tag start\n" + stanza.String())
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
				return nil, true, errors.New("invalid character '" + string(c) + "' in stream init tag\n" + stanza.String())
			}
		}
	}
	if strings.HasSuffix(stanza.String(), "/>") {
		return nil, true, errors.New("initial stream tag already closed\n" + stanza.String())
	}
	node, err := ParseStreamHeader(stanza.String())
	if err != nil {
		return nil, true, err
	}

	var attributes map[string]string = node.Attributes

	var ret InitialStreamTag

	if _, ok := attributes["anon"]; ok {
		// This is an anon connection (pre-auth)

		dev, ok := attributes["dev"]
		if !ok {
			return nil, true, errors.New("no dev attribute in anon stanza")
		}

		deviceId, err := datatypes.ParseDeviceId(dev)
		if err != nil {
			return nil, true, err
		}

		ret = InitialStreamTag{
			Attributes: attributes,
			RawStanza:  stanza.String(),
			IsAuth:     false,
			Jid:        nil,
			DeviceId:   *deviceId,
		}
	} else {
		// This is an authorized connection (post-auth)

		from, ok := attributes["from"]
		if !ok {
			return nil, true, errors.New("no from attribute in auth stanza")
		}

		jid, err := datatypes.ParseFullJid(from)
		if err != nil {
			return nil, true, err
		}

		ret = InitialStreamTag{
			Attributes: attributes,
			RawStanza:  stanza.String(),
			IsAuth:     true,
			Jid:        jid,
			DeviceId:   jid.DeviceId,
		}
	}

	// Verify stanza
	expected := crypto.MakeKTag(attributes)
	received := ret.RawStanza
	if expected != received {
		err := errors.New(
			"initial stream tag failed verification\n" +
				"Expected: " + expected + "\nReceived: " + received)
		return nil, true, err
	}

	var needsTransform bool = false

	if v, ok := attributes["x-interface"]; ok {
		ret.InterfaceIp = &v
		needsTransform = true
		delete(attributes, "x-interface")
	}
	if v, ok := attributes["x-api-key"]; ok {
		ret.ApiKey = &v
		needsTransform = true
		delete(attributes, "x-api-key")
	}
	if needsTransform {
		// Elements were removed, which invalidates the order.
		// Server must re-sort the elements.
		ret.RawStanza = crypto.MakeKTag(attributes)
	}
	return &ret, false, nil
}

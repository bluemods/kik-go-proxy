package node

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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
	// The IP address of the connected client
	ClientIp string

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

	// The version name in use by the client, not nil
	Version string

	// Optional interface IP specified by the client
	InterfaceIp *string

	// Optional API key specified by the client
	ApiKey *string
}

// Returns a unique identifier for the connecting client.
// For authed connections, this is the JID
// For anon connections, this is the Device ID (with prefix)
func (k InitialStreamTag) UserId() string {
	if k.IsAuth {
		return k.Jid.GetIdentifier()
	} else {
		return k.DeviceId.Prefix + k.DeviceId.Id
	}
}

// Returns the corresponding XMPP host name
// based on the connecting client info.
// Kik uses different host names dependent on the OS and client version.
// error is not nil if the client supplies an invalid version number.
func (k InitialStreamTag) KikHost() (*string, error) {
	ios := k.DeviceId.Prefix[1] == 'I'
	var suffix string
	var parts []string
	if ios {
		suffix = "ip"
		parts = strings.Split(k.Version, ".")
	} else {
		suffix = "an"
		parts = strings.Split(k.Version, ".")
	}
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version '" + k.Version + "'")
	}
	host := new(strings.Builder)
	host.WriteString("talk")
	for i := 0; i < 2; i++ {
		if num, err := strconv.Atoi(parts[i]); err != nil || num < 0 {
			// One of the parts is not a valid number.
			// This blocks clients from attempting to connect us to arbitrary hosts.
			return nil, fmt.Errorf("invalid version '" + k.Version + "'")
		}
		if i == 1 && ios {
			host.WriteString("0")
		} else {
			host.WriteString(parts[i])
		}
	}
	host.WriteString("0")
	host.WriteString(suffix)
	host.WriteString(".kik.com")
	ret := host.String()
	return &ret, nil
}

// Parses and verifies the initial stream tag from the client.
// If the error returned is nil, the parsing succeeded,
// and the other return values must be ignored.
// Returns: InitialStreamTag, shouldBanIp, error
func ParseInitialStreamTag(conn net.Conn) (*InitialStreamTag, bool, error) {
	defer utils.TimeMethod("ParseInitialStreamTag")()

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	var startTagSeen bool = false
	var whitespaceCount int = 0
	var characterCount int = 0

	var stanza strings.Builder
	buf := make([]byte, 1)

	for {
		if _, err := conn.Read(buf); err != nil {
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

	attrs := node.Attributes

	var ret InitialStreamTag

	if _, ok := attrs["anon"]; ok {
		// This is an anon connection (pre-auth)
		dev, ok := attrs["dev"]
		if !ok {
			return nil, true, errors.New("no dev attribute in anon stanza")
		}
		v, ok := attrs["v"]
		if !ok {
			return nil, true, errors.New("no v attribute in anon stanza")
		}

		deviceId, err := datatypes.ParseDeviceId(dev)
		if err != nil {
			return nil, true, err
		}

		ret = InitialStreamTag{
			ClientIp:   ip,
			Attributes: attrs,
			RawStanza:  stanza.String(),
			IsAuth:     false,
			Jid:        nil,
			DeviceId:   *deviceId,
			Version:    v,
		}
	} else {
		// This is an authorized connection (post-auth)
		from, ok := attrs["from"]
		if !ok {
			return nil, true, errors.New("no from attribute in auth stanza")
		}
		jid, err := datatypes.ParseFullJid(from)
		if err != nil {
			return nil, true, err
		}
		v, ok := attrs["v"]
		if !ok {
			return nil, true, errors.New("no v attribute in auth stanza")
		}

		ret = InitialStreamTag{
			ClientIp:   ip,
			Attributes: attrs,
			RawStanza:  stanza.String(),
			IsAuth:     true,
			Jid:        jid,
			DeviceId:   jid.DeviceId,
			Version:    v,
		}
	}

	// Verify stanza
	expected := crypto.MakeKTag(attrs)
	received := ret.RawStanza
	if expected != received {
		err := errors.New(
			"initial stream tag failed verification\n" +
				"Expected: " + expected + "\nReceived: " + received)
		return nil, true, err
	}

	var needsTransform bool = false

	if v, ok := attrs["x-interface"]; ok {
		ret.InterfaceIp = &v
		needsTransform = true
		delete(attrs, "x-interface")
	}
	if v, ok := attrs["x-api-key"]; ok {
		ret.ApiKey = &v
		needsTransform = true
		delete(attrs, "x-api-key")
	}
	if needsTransform {
		// Elements were removed, which invalidates the order.
		// Server must re-sort the elements.
		ret.RawStanza = crypto.MakeKTag(attrs)
	}
	return &ret, false, nil
}

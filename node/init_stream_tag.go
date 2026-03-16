package node

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/bluemods/kik-go-proxy/constants"
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

	// Optional access token provided by the client, may be nil.
	//
	// See kik/login/jwt/v1/mobile_jwt_service.proto
	//
	// and kik/login/v1/mobile_login_service.proto
	AccessToken *string
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
func (k InitialStreamTag) KikHost() (string, error) {
	isIOS := k.DeviceId.Prefix[1] == 'I'
	parts := strings.SplitN(k.Version, ".", 5)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid version '%s'", k.Version)
	}
	major, err := strconv.Atoi(parts[0])
	if major < 0 || err != nil {
		return "", fmt.Errorf("invalid version '%s'", k.Version)
	}
	minor, err := strconv.Atoi(parts[1])
	if minor < 0 || err != nil {
		return "", fmt.Errorf("invalid version '%s'", k.Version)
	}

	if isIOS {
		// This is hardcoded in the app for all working versions
		return "talk1600ip.kik.com", nil
	} else if major >= 17 && minor >= 10 {
		// This is hardcoded in the app for newer Android versions
		return "talk1600an.kik.com", nil
	} else {
		// Legacy Android path
		host := new(strings.Builder)
		host.WriteString("talk")
		for i := 0; i < 2; i++ {
			host.WriteString(parts[i])
		}
		host.WriteString("0an.kik.com")
		return host.String(), nil
	}
}

// Parses and verifies the initial stream tag from the client.
// If the error returned is nil, the parsing succeeded,
// and the other return values must be ignored.
// Returns: InitialStreamTag, shouldBanIp, error
func ParseInitialStreamTag(conn net.Conn) (*InitialStreamTag, bool, error) {
	defer utils.TimeMethod("ParseInitialStreamTag")()

	var ip = utils.ConnToIp(conn)
	var startTagSeen = false
	var whitespaceCount = 0
	var characterCount = 0

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
		if characterCount > constants.MAX_STREAM_INIT_TAG_SIZE {
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
				c == '-' || c == '+' || c == ':') {
				return nil, true, errors.New("invalid character '" + string(c) + "' in stream init tag\n" + stanza.String())
			}
		}
	}

	rawStanza := stanza.String()
	if strings.HasSuffix(rawStanza, "/>") {
		return nil, true, errors.New("initial stream tag already closed\n" + rawStanza)
	}
	node, err := ParseStreamHeader(rawStanza)
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
			RawStanza:  rawStanza,
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
		var accessToken *string
		if token, ok := attrs["access-token"]; ok && len(token) > 0 {
			accessToken = &token
		}

		ret = InitialStreamTag{
			ClientIp:    ip,
			Attributes:  attrs,
			RawStanza:   rawStanza,
			IsAuth:      true,
			Jid:         jid,
			DeviceId:    jid.DeviceId,
			Version:     v,
			AccessToken: accessToken,
		}
	}

	// Prevent quote escapes
	for k, v := range attrs {
		if strings.ContainsRune(v, '"') || strings.Contains(v, "&quot;") {
			return nil, true, fmt.Errorf(
				"invalid header key '%s=%s', value contains a double quote", k, v)
		}
	}

	// Verify stanza
	expected := crypto.MakeKTag(attrs)
	received := ret.RawStanza
	if expected != received {
		return nil, true, errors.New(
			"initial stream tag failed verification\n" +
				"Expected: " + expected + "\nReceived: " + received)
	}

	needsTransform := false

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
	if _, ok := attrs["cv"]; ok {
		// CV tokens are obsolete.
		// Remove them on the clients behalf
		// if they included them by accident on a
		// base version that no longer includes them.
		needsTransform = true
		delete(attrs, "cv")
	}
	if needsTransform {
		// Elements were removed, which invalidates the order.
		// Server must re-sort the elements.
		ret.RawStanza = crypto.MakeKTag(attrs)
	}
	return &ret, false, nil
}

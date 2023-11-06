package main

import (
	"errors"
	"net"
	"strings"
	"time"
)

type InitialStreamTag struct {
	Attributes      map[string]string
	RawStanza       string
	WhitespaceCount int
}

/*
Verifies the integrity of the stanza.
if error returned is not nil, verification failed.
*/
func (k InitialStreamTag) makeOutgoingPayload() (*string, error) {
	expected := makeKTag(k.Attributes)
	received := k.RawStanza
	if expected != received {
		err := errors.New(
			"initial stream tag failed verification\n" +
				"Expected: " + expected + "\nReceived: " + received)
		return nil, err
	}
	return &expected, nil
}

type KikInitialStreamResponse struct {
	IsOk       bool
	Attributes map[string]string
	RawStanza  string
}

func (k KikInitialStreamResponse) generateServerResponse() string {
	if !CUSTOM_BANNER {
		return k.RawStanza
	} else {
		ind := strings.LastIndex(k.RawStanza, "\"")
		if ind == -1 {
			return k.RawStanza
		} else {
			return k.RawStanza[0:ind] + "\" server=\"KikGoProxyServer\" server-version=\"1.0\"" + k.RawStanza[ind+1:]
		}
	}
}

func readKFromClient(conn net.Conn) (*InitialStreamTag, error) {
	conn.SetReadDeadline(time.Now().Add(CLIENT_INITIAL_READ_TIMEOUT_SECONDS * time.Second))
	var startTagSeen bool = false
	var whitespaceCount int = 0
	var characterCount int = 0

	kStanza := ""
	buf := make([]byte, 1)

	for {
		_, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		var c = buf[0]
		kStanza += string(c)

		characterCount++
		if characterCount > 1024 {
			return nil, errors.New("Too many characters in stream init tag\n" + kStanza)
		}

		if !startTagSeen {
			if c == '<' {
				startTagSeen = true
			} else if c != ' ' {
				return nil, errors.New("invalid character '" + string(c) + "' before tag start")
			} else {
				whitespaceCount++
				if whitespaceCount > 29 {
					return nil, errors.New("Too many whitespaces before tag start\n" + kStanza)
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
				return nil, errors.New("invalid character '" + string(c) + "' in stream init tag\n" + kStanza)
			}
		}
	}
	if strings.HasSuffix(kStanza, "/>") {
		return nil, errors.New("initial stream tag already closed\n" + kStanza)
	}
	node, err := parseInitialKString(kStanza)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(CLIENT_READ_TIMEOUT_SECONDS * time.Second))
	return &InitialStreamTag{Attributes: node.Attributes, WhitespaceCount: whitespaceCount, RawStanza: kStanza}, nil
}

func readKFromKik(kikConn net.Conn) (*KikInitialStreamResponse, error) {
	stanza := ""
	buf := make([]byte, 1)

	for {
		_, err := kikConn.Read(buf)
		if err != nil {
			return nil, err
		}
		var c = buf[0]
		stanza += string(c)
		if c == '>' {
			break
		}
	}
	k, err := parseInitialKString(stanza)
	if err != nil {
		return nil, err
	}

	return &KikInitialStreamResponse{
		IsOk:       k.Attributes["ok"] == "1",
		Attributes: k.Attributes,
		RawStanza:  stanza}, nil
}

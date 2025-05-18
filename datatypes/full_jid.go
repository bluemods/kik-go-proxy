package datatypes

import (
	"errors"
	"regexp"
)

// The device ID component is relaxed compared to Kik's regex
// Normally, it should be a random UUID with dashes omitted
var fullJidRegex = regexp.MustCompile(`^([a-z0-9._]{2,30})(_[a-z0-9]{3})?@(.*)/([A-Z]{3})(.{6,32})$`)

type FullJid struct {
	LocalPart string
	Domain    string
	DeviceId  KikDeviceId
}

func (jid FullJid) GetIdentifier() string {
	return jid.LocalPart + "@" + jid.Domain
}

func (jid FullJid) String() string {
	return jid.GetIdentifier() + "/" + jid.DeviceId.Prefix + jid.DeviceId.Id
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

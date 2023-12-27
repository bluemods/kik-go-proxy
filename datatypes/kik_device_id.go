package datatypes

import (
	"errors"
	"regexp"
)

var deviceIdRegex *regexp.Regexp = regexp.MustCompile("^([A-Z]{3})(.{6,32})$")

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

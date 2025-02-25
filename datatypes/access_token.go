package datatypes

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

type AccessToken struct {
	Raw string // Raw JWT as presented to ParseAccessToken

	IssuedAt  time.Time // When the token was issued
	NotBefore time.Time // Cannot be used before this time
	NotAfter  time.Time // Cannot be used after this time

	DeviceId     KikDeviceId // Device ID
	Jti          string      // JWT UUID
	HardwareId   string      // Android ID or IDFV
	RegisteredAt time.Time   // When the account was created
	Subject      string      // Local part of the JID
	Type         string      // "a" for access, "r" for refresh
	Version      string      // Version string, such as `17.6.9-42000`
	Locale       string      // Locale string, such as "en" or "en_US"
}

// Parses the claims in an access token or refresh token JWT.
// This method does not do any validation on the signature.
func ParseAccessToken(token string) *AccessToken {
	if len(token) == 0 {
		return nil
	}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		log.Println("ParseAccessToken: jwt is not 3 parts")
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Println("ParseAccessToken: failed to decode claims: " + err.Error())
		return nil
	}
	var r struct {
		Aud string    `json:"aud"`
		Did string    `json:"did"`
		Exp int64     `json:"exp"`
		Hid string    `json:"hid"`
		Iat int64     `json:"iat"`
		Iss string    `json:"iss"`
		Jti string    `json:"jti"`
		Loc string    `json:"loc"`
		Nbf int64     `json:"nbf"`
		Reg time.Time `json:"reg"`
		Sub string    `json:"sub"`
		Tpe string    `json:"tpe"`
		Ver string    `json:"ver"`
	}
	if err := json.Unmarshal(payload, &r); err != nil {
		log.Println("ParseAccessToken: failed to unmarshal claims: " + err.Error())
		return nil
	}
	deviceId, err := ParseDeviceId(r.Did)
	if err != nil {
		log.Println("ParseAccessToken: failed to parse device ID: " + err.Error())
		return nil
	}

	return &AccessToken{
		Raw:          token,
		IssuedAt:     time.Unix(r.Iat, 0),
		NotBefore:    time.Unix(r.Nbf, 0),
		NotAfter:     time.Unix(r.Exp, 0),
		DeviceId:     *deviceId,
		Jti:          r.Jti,
		HardwareId:   r.Hid,
		RegisteredAt: r.Reg,
		Subject:      r.Sub,
		Type:         r.Tpe,
		Version:      r.Ver,
		Locale:       r.Loc,
	}
}

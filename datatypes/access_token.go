package datatypes

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

// Deprecated: new tokens being issued are JWE encrypted
type AccessToken struct {
	Raw string // Raw JWT as presented to ParseAccessToken

	IssuedAt  time.Time // When the token was issued
	NotBefore time.Time // Cannot be used before this time
	NotAfter  time.Time // Cannot be used after this time

	Ip           string      // IP used in the last RefreshToken call
	DeviceId     KikDeviceId // Device ID
	Jti          string      // JWT ID
	Locale       string      // Locale string, such as "en" or "en_US"
	HardwareId   string      // Android ID or IDFV
	Pra          string
	Psi          string
	RegisteredAt time.Time // When the account was created
	Src          string    // Serial refresh counter. This is normally an integer. Only present in refresh token
	Subject      string    // Local part of the JID
	Type         string    // "a" for access, "r" for refresh
	UserType     string    // User type, may be empty
	Version      string    // Version string, such as `17.6.9-42000`
}

// Parses the claims in an access token or refresh token JWT.
// This method does not do any validation on the signature.
// Deprecated: new tokens issued are JWE encrypted
func ParseAccessToken(token string) *AccessToken {
	if len(token) == 0 {
		return nil
	}
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		// This is either a JWE or invalid token
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Println("ParseAccessToken: failed to decode claims: " + err.Error())
		return nil
	}
	var r struct {
		Ip  string    `json:"_ip"`
		Aud string    `json:"aud"`
		Did string    `json:"did"`
		Exp int64     `json:"exp"`
		Hid string    `json:"hid"`
		Iat int64     `json:"iat"`
		Iss string    `json:"iss"`
		Jti string    `json:"jti"`
		Loc string    `json:"loc"`
		Nbf int64     `json:"nbf"`
		Pra string    `json:"pra"`
		Psi string    `json:"psi"`
		Reg time.Time `json:"reg"`
		Src string    `json:"src"`
		Sub string    `json:"sub"`
		Tpe string    `json:"tpe"`
		Uty string    `json:"uty"`
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
		Ip:           r.Ip,
		Jti:          r.Jti,
		Locale:       r.Loc,
		HardwareId:   r.Hid,
		Pra:          r.Pra,
		Psi:          r.Psi,
		Src:          r.Src,
		RegisteredAt: r.Reg,
		Subject:      r.Sub,
		Type:         r.Tpe,
		UserType:     r.Uty,
		Version:      r.Ver,
	}
}

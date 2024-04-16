package crypto

import "encoding/base64"

func DecodeBase64(encoding *base64.Encoding, data string) []byte {
	ret, err := encoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return ret
}

func EncodeBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

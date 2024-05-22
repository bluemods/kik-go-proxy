package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Generates a valid Kik UUID.
func GenerateUUID() string {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		panic(err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Clear version, set to 4 for random
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Clear version, set to 10
	return makeId(uuid)
}

func makeId(uuid []byte) string {
	msb := uint64(uuid[0])<<56 | uint64(uuid[1])<<48 | uint64(uuid[2])<<40 | uint64(uuid[3])<<32 |
		uint64(uuid[4])<<24 | uint64(uuid[5])<<16 | uint64(uuid[6])<<8 | uint64(uuid[7])

	lsb := uint64(uuid[8])<<56 | uint64(uuid[9])<<48 | uint64(uuid[10])<<40 | uint64(uuid[11])<<32 |
		uint64(uuid[12])<<24 | uint64(uuid[13])<<16 | uint64(uuid[14])<<8 | uint64(uuid[15])

	variant := int(msb >> 62)
	bitPositions := [4][2]int{{3, 6}, {2, 5}, {7, 1}, {9, 5}}
	key := int((msb&0xFF000000)>>22) ^ int((msb&0x00FF0000)>>16) ^ int((msb&0x0000FF00)>>8)
	value := (int(msb>>uint(bitPositions[variant][1]))&1 + 1) | (int(msb>>uint(bitPositions[variant][0]))&1)<<1
	index := 1
	for i := range 6 {
		index = ((value * 7) + index) % 60
		lsb = (lsb & (^(1 << uint(index+2)))) | (uint64(key>>i&1) << uint(index+2))
	}

	var result [16]byte
	for i := range 8 {
		result[i] = byte(msb >> uint((7-i)*8))
		result[i+8] = byte(lsb >> uint((7-i)*8))
	}

	sb := strings.Builder{}
	sb.Grow(36)
	sb.WriteString(hex.EncodeToString(result[0:4]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(result[4:6]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(result[6:8]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(result[8:10]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(result[10:]))
	return sb.String()
}

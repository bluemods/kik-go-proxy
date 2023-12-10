package crypto

import (
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
)

func GenerateUUID() string {
	for {
		id, _ := makeId(uuid.New())
		if id != nil {
			return id.String()
		}
	}
}

// Mostly converted from smali bytecode after
// decompiling a known working implementation in Java
//
// returns the new ID if successful,
// or an error if the ID is not compatible
func makeId(id uuid.UUID) (*uuid.UUID, error) {
	if id.Version() != 4 {
		return nil, errors.New("UUID not V4")
	}
	bytes := id[:]
	lsb := int64(binary.BigEndian.Uint64(bytes[8:]))
	msb := int64(binary.BigEndian.Uint64(bytes[:8]))

	var i int32 = int32((msb & -1152921504606846976) >> 62)

	if i < 0 {
		// TODO: this is a workaround as ~50% of IDs generated aren't
		// compatible. Find a better way then remove this.
		return nil, errors.New("UUID not compatible")
	}
	var j int64 = (msb&-16777216)>>22 ^ (msb&16711680)>>16 ^ (msb&65280)>>8

	arr := [][]int32{{3, 6}, {2, 5}, {7, 1}, {9, 5}}

	i = shift(msb, arr[i][1]) + 1 | shift(msb, arr[i][0])<<1

	var i2 int32 = int32(0)
	var i3 int32 = int32(1)
	for i2 < 6 {
		i3 = (i3 + (i * 7)) % 60
		var i5 int32 = i3 + 2

		var preShift1 int64 = int64(shift(j, i2))
		var shift1 int64 = preShift1 << i5
		var shift2 int64 = int64(lsb &^ powerOfTwo(i5))

		lsb = shift1 | shift2

		// fmt.Printf("i=%d, j=%d, i3=%d, i5=%d, lsb=%d, i2=%d, ps1=%d, s1=%d, s2=%d\n",
		//            i, j, i3, i5, lsb, i2, preShift1, shift1, shift2)
		i2++
	}

	newBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(newBytes[:8], uint64(msb))
	binary.BigEndian.PutUint64(newBytes[8:], uint64(lsb))
	newUuid, _ := uuid.FromBytes(newBytes)
	return &newUuid, nil
}

func shift(j int64, i int32) int32 {
	var one int64 = 1
	if i > 32 {
		return int32((j >> 32 & one << i)) >> i
	} else {
		ret := one << i
		ret = ret & j
		return int32(ret) >> i
	}
}

func powerOfTwo(i int32) int64 {
	return int64(1) << i
}

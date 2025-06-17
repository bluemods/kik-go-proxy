package crypto

import (
	"bytes"
	"crypto"
	"slices"
	"strings"

	orderedmap "github.com/wk8/go-ordered-map/v2"

	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
)

type sortingMode struct {
	base   int32
	offset int32
}

var (
	baseOrdering     = sortingMode{base: -310256979, offset: 13}
	extendedOrdering = sortingMode{base: -1964139357, offset: 7}
)

// Makes a 'k' tag, including correct spaces and order.
func MakeKTag(attrs map[string]string) string {
	newMap := orderedmap.New[string, string]()
	for k, v := range attrs {
		newMap.Set(k, v)
	}

	base := sortKikMap(newMap, baseOrdering)
	hashCode := hashStrongMap(baseOrdering, base) % int32(29)

	if hashCode < 0 {
		hashCode += int32(29)
	}

	k := new(strings.Builder)
	k.WriteString(strings.Repeat(" ", int(hashCode)))
	k.WriteString("<k")

	extended := sortKikMap(base, extendedOrdering)
	for pair := extended.Oldest(); pair != nil; pair = pair.Next() {
		k.WriteString(" " + pair.Key + "=\"" + pair.Value + "\"")
	}
	k.WriteString(">")
	return k.String()
}

func sortKikMap(om *orderedmap.OrderedMap[string, string], mode sortingMode) *orderedmap.OrderedMap[string, string] {
	ret := orderedmap.New[string, string]()

	omCopy := createCopy(om)

	keySet := []string{}
	for pair := omCopy.Oldest(); pair != nil; pair = pair.Next() {
		keySet = append(keySet, pair.Key)
	}
	slices.Sort(keySet)

	for omCopy.Len() > 0 {
		strongMap := createCopy(&omCopy)

		if strongMap.Oldest() != nil {
			hashCode := hashStrongMap(mode, &strongMap) % int32(strongMap.Len())
			if hashCode < 0 {
				hashCode += int32(strongMap.Len())
			}

			key := keySet[hashCode]
			val, _ := omCopy.Get(key)
			ret.Set(key, val)

			keySet = remove(keySet, hashCode)
			omCopy.Delete(key)
		}
	}
	return ret
}

func hashStrongMap(mode sortingMode, om *orderedmap.OrderedMap[string, string]) int32 {
	keys := keySet(om)
	reversedKeySet := copyAndReverse(keys)

	forwardBuffer := new(bytes.Buffer)
	backwardBuffer := new(bytes.Buffer)

	for _, v := range keys {
		forwardBuffer.Write([]byte(v))
		res, _ := om.Get(v)
		forwardBuffer.Write([]byte(res))
	}
	for _, v := range reversedKeySet {
		backwardBuffer.Write([]byte(v))
		res, _ := om.Get(v)
		backwardBuffer.Write([]byte(res))
	}

	forwardBytes := forwardBuffer.Bytes()
	backwardBytes := backwardBuffer.Bytes()

	base := mode.base
	offset := mode.offset

	hashes := []int32{
		hashBytes(crypto.SHA256, forwardBytes),
		hashBytes(crypto.SHA1, forwardBytes),
		hashBytes(crypto.MD5, backwardBytes),
	}
	return base ^ hashes[0]<<offset ^ hashes[2]<<(offset*2) ^ hashes[1]<<offset ^ hashes[0]
}

func mangleBytes(bytes []byte) int32 {
	var j int = 0

	for k := 0; k < len(bytes); k += 4 {
		j ^= ((byteToSignedInt(int(bytes[k+3]))) << int32(24)) |
			(byteToSignedInt(int(bytes[k+2])) << int32(16)) |
			(byteToSignedInt(int(bytes[k+1])) << int32(8)) |
			(byteToSignedInt(int(bytes[k])))
	}
	return int32(j)
}

func byteToSignedInt(num int) int {
	if num > 127 {
		return (256 - num) * (-1)
	} else {
		return num
	}
}

func hashBytes(hash crypto.Hash, data []byte) int32 {
	h := hash.New()
	h.Write(data)
	return mangleBytes(h.Sum(nil))
}

// Ordered map helper functions

func createCopy(om *orderedmap.OrderedMap[string, string]) orderedmap.OrderedMap[string, string] {
	ret := orderedmap.New[string, string]()
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		ret.Set(pair.Key, pair.Value)
	}
	return *ret
}

func copyAndReverse(elements []string) []string {
	ret := make([]string, len(elements))
	for i := range elements {
		ret[len(elements)-1-i] = elements[i]
	}
	return ret
}

func remove(slice []string, s int32) []string {
	return append(slice[:s], slice[s+1:]...)
}

func keySet(om *orderedmap.OrderedMap[string, string]) []string {
	keys := make([]string, om.Len())
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, pair.Key)
	}
	slices.Sort(keys)
	return keys
}

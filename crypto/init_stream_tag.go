package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"slices"
	"strings"

	orderedmap "github.com/wk8/go-ordered-map/v2"
)

const (
	SHA_256 = 0
	SHA_1   = 1
	MD5     = 2
)

type SortingMode struct {
	Base   int
	Offset int
}

/*
Makes a 'k' tag, including correct spaces and order.
*/
func MakeKTag(attrs map[string]string) string {
	BaseOrdering := &SortingMode{Base: -310256979, Offset: 13}
	ExtendedOrdering := &SortingMode{Base: -1964139357, Offset: 7}

	newMap := orderedmap.New[string, string]()
	for k, v := range attrs {
		newMap.Set(k, v)
	}

	base := sortKikMap(newMap, *BaseOrdering)
	hashCode := hashStrongMap(*BaseOrdering, base) % int32(29)

	if hashCode < 0 {
		hashCode += int32(29)
	}

	// fmt.Println(fmt.Sprintf("hashCode: %d", hashCode))

	k := strings.Repeat(" ", int(hashCode))
	k += "<k"

	extended := sortKikMap(base, *ExtendedOrdering)
	for pair := extended.Oldest(); pair != nil; pair = pair.Next() {
		k += " " + pair.Key + "=\"" + pair.Value + "\""
	}
	k += ">"
	return k
}

func sortKikMap(om *orderedmap.OrderedMap[string, string], mode SortingMode) *orderedmap.OrderedMap[string, string] {
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

func createCopy(om *orderedmap.OrderedMap[string, string]) orderedmap.OrderedMap[string, string] {
	ret := orderedmap.New[string, string]()
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		ret.Set(pair.Key, pair.Value)
	}
	return *ret
}

func remove(slice []string, s int32) []string {
	return append(slice[:s], slice[s+1:]...)
}

func keySet(om *orderedmap.OrderedMap[string, string]) []string {
	keySet := make([]string, om.Len())
	for pair := om.Oldest(); pair != nil; pair = pair.Next() {
		keySet = append(keySet, pair.Key)
	}
	slices.Sort(keySet)
	return keySet
}

func hashStrongMap(mode SortingMode, om *orderedmap.OrderedMap[string, string]) int32 {
	copy := createCopy(om)

	keySet := keySet(&copy)
	reversedKeySet := copyAndReverse(keySet)

	bytesForward := ""
	bytesBackward := ""

	for _, v := range keySet {
		bytesForward += v
		res, _ := copy.Get(v)
		bytesForward += res
	}
	for _, v := range reversedKeySet {
		bytesBackward += v
		res, _ := copy.Get(v)
		bytesBackward += res
	}

	// fmt.Println("Forward:  " + bytesForward)
	// fmt.Println("Backward: " + bytesBackward)

	base := int32(mode.Base)
	offset := int32(mode.Offset)

	hashes := []int32{}
	hashes = append(hashes, hashString(SHA_256, bytesForward))
	hashes = append(hashes, hashString(SHA_1, bytesForward))
	hashes = append(hashes, 0) // Can be removed
	hashes = append(hashes, 0) // Can be removed
	hashes = append(hashes, 0) // Can be removed
	hashes = append(hashes, hashString(MD5, bytesBackward))

	/*for i, number := range hashes {
		if i == 0 || i == 1 || i == 5 {
			fmt.Println(fmt.Sprintf("Hash %d: %s", i, strconv.Itoa(int(number))))
		}
	}*/

	return base ^ hashes[0]<<offset ^ hashes[5]<<(offset*2) ^ hashes[1]<<offset ^ hashes[0]
}

func mangleBytes(bytes []byte) int32 {
	var j int = 0

	for k := 0; k < len(bytes); k += 4 {
		j ^= ((byteToSignedInt(int(bytes[k+3]))) << int32(24)) |
			 (byteToSignedInt(int(bytes[k+2])) << int32(16))   |
			 (byteToSignedInt(int(bytes[k+1])) << int32(8))    |
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

func copyAndReverse(elements []string) []string {
	ret := make([]string, len(elements))
	for i := range elements {
		ret[len(elements)-1-i] = elements[i]
	}
	return ret
}

func hashString(digestType int, data string) int32 {
	if digestType == SHA_256 {
		h := sha256.Sum256([]byte(data))
		return mangleBytes(h[:])
	}
	if digestType == SHA_1 {
		h := sha1.New()
		h.Write([]byte(data))
		hash := h.Sum(nil)
		return mangleBytes(hash)
	}
	if digestType == MD5 {
		h := md5.New()
		h.Write([]byte(data))
		hash := h.Sum(nil)
		return mangleBytes(hash)
	}
	panic("wtf")
}
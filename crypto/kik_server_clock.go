package crypto

import (
	"time"
)

var _serverTimeOffset int64 = 0

// This should only be used for the stream header (<k/>)
func MakeCryptoTimestamp() int64 {
    var j int64 = GetServerTime()
    var j2 int64 = (((j & 0xff00) >> 8) ^ ((j & 0xff0000) >> 16) ^ ((j & 0xff000000) >> 24)) & 30
    var j3 int64 = (j & 224) >> 5
    var j4 int64 = j & -255
    if (j2 % 4 == 0) {
        j3 = (j3 / 3) * 3
    } else {
        j3 = (j3 / 2) * 2
    }
    return j4 | j3 << 5 | j2
}

// Returns a timestamp synchronized with Kik's server.
// 
// Should be used for all outgoing stanzas in the cts and kik.timestamp attributes
func GetServerTime() int64 {
	return time.Now().UnixMilli() + _serverTimeOffset
}

func SetServerTimeOffset(offset int64) {
	_serverTimeOffset = offset
}
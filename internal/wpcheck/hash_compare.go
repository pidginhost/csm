package wpcheck

import (
	"crypto/subtle"
	"encoding/hex"
)

const maxHexDigestLength = 64

func constantTimeHexDigestEqual(actualDigest []byte, expectedHex string) bool {
	actualHexLen := len(actualDigest) * 2
	if actualHexLen == 0 || actualHexLen > maxHexDigestLength {
		return false
	}

	var actual [maxHexDigestLength]byte
	var expected [maxHexDigestLength]byte
	hex.Encode(actual[:actualHexLen], actualDigest)
	if len(expectedHex) >= actualHexLen {
		copy(expected[:actualHexLen], expectedHex[:actualHexLen])
	} else {
		copy(expected[:actualHexLen], expectedHex)
	}

	lengthEqual := 0
	if len(expectedHex) == actualHexLen {
		lengthEqual = 1
	}
	digestEqual := subtle.ConstantTimeCompare(actual[:actualHexLen], expected[:actualHexLen])
	return lengthEqual&digestEqual == 1
}

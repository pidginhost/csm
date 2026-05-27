package wpcheck

import (
	"crypto/md5" // #nosec G501 -- test input mirrors wordpress.org core MD5 references.
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestConstantTimeHexDigestEqual(t *testing.T) {
	md5Digest := md5.Sum([]byte("wordpress core"))
	md5Hex := hex.EncodeToString(md5Digest[:])
	shaDigest := sha256.Sum256([]byte("wordpress plugin"))
	shaHex := hex.EncodeToString(shaDigest[:])

	tests := []struct {
		name        string
		actual      []byte
		expectedHex string
		want        bool
	}{
		{
			name:        "md5 match",
			actual:      md5Digest[:],
			expectedHex: md5Hex,
			want:        true,
		},
		{
			name:        "sha256 match",
			actual:      shaDigest[:],
			expectedHex: shaHex,
			want:        true,
		},
		{
			name:        "same length mismatch",
			actual:      md5Digest[:],
			expectedHex: strings.Repeat("0", len(md5Hex)),
			want:        false,
		},
		{
			name:        "matching prefix but too short",
			actual:      md5Digest[:],
			expectedHex: md5Hex[:len(md5Hex)-1],
			want:        false,
		},
		{
			name:        "matching prefix but too long",
			actual:      md5Digest[:],
			expectedHex: md5Hex + "0",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := constantTimeHexDigestEqual(tt.actual, tt.expectedHex); got != tt.want {
				t.Fatalf("constantTimeHexDigestEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

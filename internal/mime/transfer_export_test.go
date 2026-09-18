package mime

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDecodeTransferVariantsCleanInputHasOneReading(t *testing.T) {
	want := []byte("<html>hello</html>")
	got := DecodeTransferVariants(" Base64 ", []byte(base64.StdEncoding.EncodeToString(want)))
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("variants = %q, want exactly [%q]", got, want)
	}
}

func TestDecodeTransferVariantsKeepsEveryReadingOfAmbiguousPadding(t *testing.T) {
	got := DecodeTransferVariants("base64", []byte("YWI=QUJD"))
	if len(got) < 2 {
		t.Fatalf("variants = %q, want the continued decode and the padded prefix", got)
	}
	if !bytes.Equal(got[0], []byte("abABC")) {
		t.Fatalf("first variant = %q, want abABC", got[0])
	}
	var prefix bool
	for _, v := range got[1:] {
		prefix = prefix || bytes.Equal(v, []byte("ab"))
	}
	if !prefix {
		t.Fatalf("variants = %q, want the padded prefix ab among them", got)
	}
}

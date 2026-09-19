package phptaintipc

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzLookupJSONField(f *testing.F) {
	for _, seed := range []string{`null`, `-1`, `"literal"`, `{}`, `{"basis":5}`, `[]`, `{"Basis":1,"Basis":2}`, `{`, `{} {}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _, err := lookupJSONField(raw, "basis")
		if !json.Valid(raw) {
			if err == nil {
				t.Fatal("invalid JSON accepted")
			}
			return
		}

		// Nested keys are independent; arbitrary valid JSON values must
		// survive inspection without being interpreted as sibling fields.
		object := append([]byte(`{"nested":{"Basis":null},"BaSiS":`), raw...)
		object = append(object, '}')
		got, ok, err := lookupJSONField(object, "basis")
		if err != nil || !ok || !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(raw)) {
			t.Fatalf("single field = %s, %v, %v; want %s", got, ok, err, raw)
		}
		for _, duplicate := range []string{`"BaSiS"`, `"basis"`, `"\u0042asis"`} {
			object := append([]byte(`{"BaSiS":`), raw...)
			object = append(object, []byte(`,`+duplicate+`:null}`)...)
			if _, _, err := lookupJSONField(object, "basis"); err == nil {
				t.Fatalf("duplicate field %s accepted", duplicate)
			}
		}
	})
}

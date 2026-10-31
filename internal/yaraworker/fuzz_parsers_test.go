package yaraworker

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/yaraipc"
)

func FuzzDecodeWorkerArgs(f *testing.F) {
	for _, payload := range []string{
		`{"sources":[{"name":"a.yar","size":0}]}`,
		`{"max_bytes":4}`, `null`, `{}`, `{"sources":[]} {}`,
		"{\"sources\":[{\"name\":\"\xff\",\"size\":0}]}",
	} {
		f.Add([]byte(payload))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, out := range []any{new(yaraipc.CompileArgs), new(yaraipc.ScanFDArgs)} {
			if err := decodeArgs(payload, out); err != nil {
				continue
			}
			if !json.Valid(payload) || !utf8.Valid(payload) || !bytes.HasPrefix(bytes.TrimSpace(payload), []byte("{")) {
				t.Fatalf("accepted malformed worker args: %q", payload)
			}
		}
	})
}

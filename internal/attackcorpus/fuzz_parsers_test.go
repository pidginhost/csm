package attackcorpus

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func FuzzLoadManifest(f *testing.F) {
	for _, sample := range []Sample{maliciousSample(), controlSample()} {
		data, err := json.Marshal(sample)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"kind":"control","kind":"malicious"}`))
	f.Add([]byte(`{"files":[{"path":"../outside","b64":"a.b64"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		writeManifest(t, filepath.Join(root, "webshell", caseName), data)
		samples, err := Load(root, "private")
		if err != nil {
			if samples != nil {
				t.Fatal("Load returned a partial corpus on failure")
			}
			return
		}
		if len(samples) != 1 || samples[0].Name != caseName || samples[0].Category != "webshell" {
			t.Fatal("Load lost the sample or its identity")
		}
		if len(samples[0].Files) == 0 || len(samples[0].Expect) != 3 {
			t.Fatal("Load accepted an incomplete sample")
		}
		for _, file := range samples[0].Files {
			content, err := samples[0].Content(file)
			if err != nil || len(content) == 0 {
				t.Fatal("Load accepted an unreadable or empty sample file")
			}
		}
	})
}

package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func FuzzRemovedFileState(f *testing.F) {
	f.Add("/example/target.php")
	f.Add("/example/target-\xff.php")
	f.Add("/example/target-\ufffd.php")
	f.Add("/example/../target.php")
	f.Add("/example/target\x00.php")
	f.Fuzz(func(t *testing.T, path string) {
		now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		before := RemovedFile{Path: path, SHA256: strings.Repeat("a", 64), Size: 1, At: now, Action: "quarantine", Seq: 42}
		data, err := json.Marshal(savedRemoval(before))
		if err != nil {
			t.Fatal(err)
		}
		var saved savedRemovedFile
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		got, valid := saved.removal(now)
		if valid != validRemovedFile(before, now) {
			t.Fatal("serialization changed evidence validity")
		}
		if valid && (got.Path != before.Path || got.RestoreKey() != before.RestoreKey() || got.Seq != 0) {
			t.Fatal("serialization changed removal identity or replayed its sequence")
		}
	})
}

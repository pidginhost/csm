//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
)

func TestRestoredFileResponsePreservesConcurrentReplacement(t *testing.T) {
	for _, when := range []string{"reservation", "lease"} {
		t.Run(when, func(t *testing.T) {
			cfg, homes := fileResponseFixture(t, "")
			withActionSink(t)
			const original = "removed content"
			const replacement = "updated content"
			path := responseFile(t, homes, "alice", "restore.php", []byte(original)).FilePath
			snapshot := actionlog.Stat(path)
			rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "quarantine")
			finding := restoredFinding(path)
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			changed := false
			rewrite := func() error {
				changed = true
				if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
					return err
				}
				return os.Chtimes(path, info.ModTime(), info.ModTime())
			}
			if when == "reservation" {
				write := writeFileResponseState
				writeFileResponseState = func(statePath string, mode os.FileMode, data any) error {
					if !changed {
						if err := rewrite(); err != nil {
							return err
						}
					}
					return write(statePath, mode, data)
				}
				t.Cleanup(func() { writeFileResponseState = write })
			} else {
				before := quarantineBeforeLease
				quarantineBeforeLease = func(string) error { return rewrite() }
				t.Cleanup(func() { quarantineBeforeLease = before })
			}
			if got := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(got) != 0 {
				t.Fatalf("changed source was quarantined: %+v", got)
			}
			if !changed {
				t.Fatal("response did not reach the interleaved rewrite")
			}
			assertResponseFile(t, path, []byte(replacement))
			state, err := readFileResponseState(filepath.Join(cfg.StatePath, fileResponseStateName), fileResponseNow())
			if err != nil || len(state.Attempts) != 1 || state.Attempts[0].Failed || state.Attempts[0].Pending {
				t.Fatalf("refusal must consume one attempt without a failure: %+v, %v", state, err)
			}
		})
	}
}

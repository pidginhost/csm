//go:build linux && journal && kernelintegration

package maillog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelJournalDelivery(t *testing.T) {
	for _, history := range []bool{false, true} {
		t.Run(fmt.Sprintf("history=%v", history), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			suffix := fmt.Sprint(time.Now().UnixNano())
			units := []string{"csm-mail-first-" + suffix, "csm-mail-second-" + suffix}
			directory := t.TempDir()
			started := make(map[string]bool)
			command := func(args ...string) {
				t.Helper()
				runCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				output, err := exec.CommandContext(runCtx, args[0], args[1:]...).CombinedOutput()
				if err != nil {
					t.Fatalf("%s: %v: %s", args[0], err, output)
				}
			}
			t.Cleanup(func() {
				for unit := range started {
					cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
					output, err := exec.CommandContext(cleanupCtx, "systemctl", "stop", unit+".service").CombinedOutput()
					stop()
					if err != nil {
						t.Errorf("stop emitter: %v: %s", err, output)
					}
				}
			})
			emit := func(unit, message string) {
				t.Helper()
				path := filepath.Join(directory, unit)
				if err := os.WriteFile(path, []byte(message+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if started[unit] {
					command("systemctl", "restart", unit+".service")
					return
				}
				command("systemd-run", "--quiet", "--unit="+unit, "--property=Type=oneshot", "--remain-after-exit", "/bin/cat", path)
				started[unit] = true
			}
			if history {
				for _, unit := range units {
					emit(unit, "old-record")
				}
				command("journalctl", "--sync")
			}
			lines, err := NewJournalReader(units).Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Only systemd can supply the trusted unit field used by this filter.
			emit("csm-mail-unrelated-"+suffix, "wrong-unit")
			for i, unit := range units {
				emit(unit, fmt.Sprintf("csm-mail-%d", i))
			}
			got := make(map[string]string)
			deadline := time.After(10 * time.Second)
			for len(got) < 2 {
				select {
				case line, ok := <-lines:
					if !ok {
						t.Fatal("reader stopped before delivery")
					}
					if line.Source != "journal" {
						t.Fatalf("source = %q", line.Source)
					}
					if _, exists := got[line.Unit]; exists {
						t.Fatalf("duplicate line: %+v", line)
					}
					got[line.Unit] = line.Message
				case <-deadline:
					t.Fatalf("journal delivery timed out: %+v", got)
				}
			}
			for i, unit := range units {
				if got[unit+".service"] != fmt.Sprintf("csm-mail-%d", i) {
					t.Fatalf("wrong journal content: %+v", got)
				}
			}
			cancel()
			select {
			case line, ok := <-lines:
				if ok {
					t.Fatalf("unexpected extra line: %+v", line)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("journal reader did not close on cancellation")
			}
		})
	}
}

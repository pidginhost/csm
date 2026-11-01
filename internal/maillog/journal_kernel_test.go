//go:build linux && journal && kernelintegration

package maillog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
			command := func(args ...string) string {
				t.Helper()
				runCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				output, err := exec.CommandContext(runCtx, args[0], args[1:]...).CombinedOutput()
				if err != nil {
					t.Fatalf("%s: %v: %s", args[0], err, output)
				}
				return strings.TrimSpace(string(output))
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
			queue := NewQueue()
			lines, err := NewJournalReader(units, queue).Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Only systemd can supply the trusted unit field used by this filter.
			emit("csm-mail-unrelated-"+suffix, "wrong-unit")
			for i, forged := range []struct{ ident, message string }{
				{"postfix/smtpd", "warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: x, sasl_username=" + suffix},
				{"postfix/smtpd", "4ABC123: client=unknown[203.0.113.7], sasl_method=PLAIN, sasl_username=" + suffix},
				{"dovecot", "auth: sql(" + suffix + ",203.0.113.7): Password mismatch"},
			} {
				unit := fmt.Sprintf("csm-mail-forged-%d-%s", i, suffix)
				started[unit] = true
				command("systemd-run", "--quiet", "--unit="+unit, "--property=Type=oneshot", "--remain-after-exit",
					"--property=User=nobody", "/usr/bin/logger", "--socket-errors=on", "-p", "mail.info", "-t", forged.ident, forged.message)
				command("journalctl", "--sync")
				// Verify the forged message reached journald, so its absence
				// from the reader proves filtering rather than failed logging.
				logged := command("journalctl", "--no-pager", "-o", "cat", "-t", forged.ident, "--grep="+suffix)
				if !strings.Contains(logged, forged.message) {
					t.Fatalf("forged %s message did not reach the journal", forged.ident)
				}
			}
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
					if line.Position.Stream != "journal" || line.Position.Cursor == "" || line.Position.ObservedAt.IsZero() {
						t.Fatalf("journal line lost its position: %+v", line)
					}
					rest, tagged := strings.CutPrefix(line.Message, line.Position.ObservedAt.Format(time.RFC3339Nano)+" cat[")
					pid, message, delimited := strings.Cut(rest, "]: ")
					if n, parseErr := strconv.ParseUint(pid, 10, 32); !tagged || !delimited || parseErr != nil || n == 0 {
						t.Fatalf("journal line lost its process tag: %+v", line)
					}
					got[line.Unit] = message
					line.Process(func(Line) bool { return true })
				case <-deadline:
					t.Fatalf("journal delivery timed out: %+v", got)
				}
			}
			for i, unit := range units {
				if got[unit+".service"] != fmt.Sprintf("csm-mail-%d", i) {
					t.Fatalf("wrong journal content: %+v", got)
				}
			}
			if health := queue.QueueStatuses(time.Now())["delivery"]; health.Depth != 0 || health.InFlight != 0 || health.DroppedTotal != 0 {
				t.Fatalf("journal delivery left unfinished work: %+v", health)
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

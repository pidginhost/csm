//go:build yara

package yaraworker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/yaraipc"
)

// End-to-end recovery against the real YARA-X engine: a worker that boots with
// a rules directory that fails to compile must stay alive, report the compile
// error and zero rules over Ping, and then recover on an OpReload once the
// rules on disk are fixed. Before the fix the handler no-op'd Reload on a nil
// scanner, so YARA stayed dead for the worker's lifetime.
func TestRunRecoversFromBadRulesOnReload(t *testing.T) {
	dir := shortTmpDir(t)
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(rulesDir, "rules.yar")
	// Syntactically broken rule: no closing brace / condition body.
	if err := os.WriteFile(rulePath, []byte("rule broken { condition: "), 0o600); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "w.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{SocketPath: sock, RulesDir: rulesDir}) }()
	waitForSocket(t, sock, 2*time.Second)

	c := yaraipc.NewClient(sock, 2*time.Second)
	defer func() { _ = c.Close() }()

	ping, err := c.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !ping.Alive {
		t.Fatal("worker must stay alive despite a failed compile")
	}
	if ping.RuleCount != 0 || ping.CompileError == "" {
		t.Fatalf("pre-recovery ping = %+v, want 0 rules + compile error", ping)
	}

	// Fix the rules and reload.
	good := "rule good { strings: $a = \"malz\" condition: $a }"
	if err := os.WriteFile(rulePath, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	rr, err := c.Reload(yaraipc.ReloadArgs{})
	if err != nil {
		t.Fatalf("Reload after fixing rules: %v", err)
	}
	if rr.RuleCount < 1 || rr.CompileError != "" {
		t.Fatalf("Reload result = %+v, want >=1 rule + no compile error", rr)
	}

	ping, err = c.Ping()
	if err != nil {
		t.Fatalf("Ping after recovery: %v", err)
	}
	if ping.RuleCount < 1 || ping.CompileError != "" {
		t.Errorf("post-recovery ping = %+v, want rules + no compile error", ping)
	}

	cancel()
	<-done
}

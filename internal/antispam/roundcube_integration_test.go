//go:build integration

package antispam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Requires PHP on PATH. Run with -tags integration -run Roundcube.
func TestRoundcubeScript(t *testing.T) {
	configured := RenderRoundcube() + "$config['plugins'] = array('markasjunk');\n"
	for _, tc := range []struct {
		name, defaults, config string
		want                   RoundcubeState
		wantErr                bool
	}{
		{"loaded", "<?php\n$config['junk_mbox'] = 'INBOX.Trash';\n", configured,
			RoundcubeState{JunkMbox: RoundcubeJunkFolder, SpamMbox: RoundcubeJunkFolder, MarkAsJunk: true}, false},
		{"load order", configured, "<?php\n$config['junk_mbox'] = 'Junk';\n",
			RoundcubeState{JunkMbox: "Junk", SpamMbox: RoundcubeJunkFolder, MarkAsJunk: true}, false},
		{"missing defaults", "", configured, RoundcubeState{}, true},
		{"missing config", configured, "", RoundcubeState{}, true},
		{"syntax error", configured, "<?php\ninvalid syntax\n", RoundcubeState{}, true},
		{"newline in folder", configured, "<?php\n$config['junk_mbox'] = \"INBOX.\nspam\";\n", RoundcubeState{}, true},
		{"carriage return in folder", configured, "<?php\n$config['markasjunk_spam_mbox'] = \"INBOX.\rspam\";\n", RoundcubeState{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "config"), 0o700); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{"defaults.inc.php": tc.defaults, "config.inc.php": tc.config} {
				if content != "" {
					if err := os.WriteFile(filepath.Join(dir, "config", name), []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			run := func(ctx context.Context, limit time.Duration, _ string, args ...string) CommandResult {
				ctx, cancel := context.WithTimeout(ctx, limit)
				defer cancel()
				// The test runs as its own user, so the privilege drop is
				// skipped; only PHP's arguments are kept.
				phpArgs := append([]string(nil), args[slices.Index(args, cpanelPHP)+1:]...)
				root := strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(dir + "/")
				phpArgs[len(phpArgs)-1] = strings.ReplaceAll(phpArgs[len(phpArgs)-1], roundcubeDir, root)
				cmd := exec.CommandContext(ctx, "php", phpArgs...)
				cmd.Env = append(os.Environ(), "DNS=localhost")
				stdout, err := cmd.Output()
				return CommandResult{Stdout: string(stdout), Err: err}
			}
			got, err := RoundcubeEffective(context.Background(), run, 65534, 65534)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("state = %+v, err = %v; want %+v, error=%t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

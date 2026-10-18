package antispam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenderRoundcubeExact(t *testing.T) {
	want := "<?php\n# csm-managed-version: 1\n$config['junk_mbox'] = 'INBOX.spam';\n$config['markasjunk_spam_mbox'] = 'INBOX.spam';\n"
	if got := RenderRoundcube(); got != want {
		t.Fatalf("include = %q", got)
	}
	if !ManagedFor(TargetRoundcube, RenderRoundcube()) {
		t.Fatal("rendered include is not recognised as CSM's")
	}
}

func TestParseRoundcubeState(t *testing.T) {
	got, err := ParseRoundcubeState("junk_mbox=INBOX.spam\nspam_mbox=INBOX.spam\nmarkasjunk=1\n")
	if err != nil || got != (RoundcubeState{JunkMbox: "INBOX.spam", SpamMbox: "INBOX.spam", MarkAsJunk: true}) {
		t.Fatalf("state=%+v err=%v", got, err)
	}
	got, err = ParseRoundcubeState("markasjunk=0\njunk_mbox=INBOX.Trash\nspam_mbox=\n")
	if err != nil || got != (RoundcubeState{JunkMbox: "INBOX.Trash"}) {
		t.Fatalf("other order: state=%+v err=%v", got, err)
	}
	for name, out := range map[string]string{
		"extra line":   "junk_mbox=a\nspam_mbox=b\nmarkasjunk=1\nother=x\n",
		"missing line": "junk_mbox=a\nmarkasjunk=1\n",
		"repeated":     "junk_mbox=a\njunk_mbox=b\nmarkasjunk=1\n",
		"garbage":      "PHP Warning: something\n",
		"bad flag":     "junk_mbox=a\nspam_mbox=b\nmarkasjunk=yes\n",
		"empty":        "",
		"blank line":   "junk_mbox=a\nspam_mbox=b\nmarkasjunk=1\n\n",
	} {
		if _, err := ParseRoundcubeState(out); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRoundcubeEffectiveRunsPHP(t *testing.T) {
	var gotName string
	var gotArgs []string
	run := func(_ context.Context, limit time.Duration, name string, args ...string) CommandResult {
		gotName, gotArgs = name, args
		if limit <= 0 {
			t.Error("no time limit")
		}
		return CommandResult{Stdout: "junk_mbox=INBOX.spam\nspam_mbox=INBOX.spam\nmarkasjunk=1\n"}
	}
	state, err := RoundcubeEffective(context.Background(), run)
	if err != nil || !state.MarkAsJunk {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	line := gotName + " " + strings.Join(gotArgs, " ")
	for _, want := range []string{"env DNS=localhost /usr/local/cpanel/3rdparty/bin/php -d display_errors=0 -r ",
		"RCMAIL_VERSION", "RCUBE_INSTALL_PATH", "config/config.inc.php", "junk_mbox=", "spam_mbox=", "markasjunk="} {
		if !strings.Contains(line, want) {
			t.Errorf("command lacks %q: %s", want, line)
		}
	}
	for _, banned := range []string{"var_dump", "print_r", "var_export"} {
		if strings.Contains(line, banned) {
			t.Errorf("script dumps configuration with %s", banned)
		}
	}
	failing := func(context.Context, time.Duration, string, ...string) CommandResult {
		return CommandResult{Stdout: "junk_mbox=INBOX.spam\n", Err: errors.New("exit status 255")}
	}
	if _, err := RoundcubeEffective(context.Background(), failing); err == nil {
		t.Fatal("failed PHP accepted")
	}
}

func TestRoundcubeStateDescribe(t *testing.T) {
	got := RoundcubeState{JunkMbox: "INBOX.Trash", SpamMbox: "", MarkAsJunk: true}.Describe()
	if got != `Roundcube loads junk_mbox "INBOX.Trash", markasjunk_spam_mbox "", markasjunk on` {
		t.Fatalf("describe = %q", got)
	}
	long := RoundcubeState{JunkMbox: strings.Repeat("x", 300) + "\u202e"}.Describe()
	if len(long) > 200 || strings.ContainsRune(long, '\u202e') {
		t.Fatalf("describe kept a long or control value: %q", long)
	}
}

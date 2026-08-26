package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestParsePHPShieldLineBlockPath(t *testing.T) {
	line := `[2026-04-12 10:00:00] BLOCK_PATH ip=203.0.113.5 script=/tmp/evil.php details=blocked dangerous path`
	f := parsePHPShieldLine(line)
	if f == nil {
		t.Fatal("expected finding for BLOCK_PATH")
	}
	if f.Check != "php_shield_block" {
		t.Errorf("Check = %q", f.Check)
	}
}

func TestParsePHPShieldLineWebshellParam(t *testing.T) {
	line := `[2026-04-12 10:00:00] WEBSHELL_PARAM ip=203.0.113.5 script=/home/user/public_html/cmd.php details=cmd parameter detected`
	f := parsePHPShieldLine(line)
	if f == nil {
		t.Fatal("expected finding for WEBSHELL_PARAM")
	}
	if f.Check != "php_shield_webshell" {
		t.Errorf("Check = %q", f.Check)
	}
}

func TestParsePHPShieldLineBlockedWebshell(t *testing.T) {
	line := `[2026-04-12 10:00:00] BLOCK_WEBSHELL ip=203.0.113.5 script=/home/user/public_html/shell.php details=signature matched`
	f := parsePHPShieldLine(line)
	if f == nil || f.Check != "php_shield_webshell" {
		t.Fatalf("blocked webshell finding = %+v", f)
	}
}

func TestParsePHPShieldLineEvalFatal(t *testing.T) {
	line := `[2026-04-12 10:00:00] EVAL_FATAL ip=203.0.113.5 script=/home/user/public_html/plugin.php details=nested eval chain`
	f := parsePHPShieldLine(line)
	if f == nil {
		t.Fatal("expected finding for EVAL_FATAL")
	}
	if f.Check != "php_shield_eval" {
		t.Errorf("Check = %q", f.Check)
	}
}

func TestParsePHPShieldLineUnknownEvent(t *testing.T) {
	line := `[2026-04-12 10:00:00] UNKNOWN_EVENT ip=1.2.3.4`
	if f := parsePHPShieldLine(line); f != nil {
		t.Errorf("unknown event should return nil, got %+v", f)
	}
}

func TestParsePHPShieldLineEmpty(t *testing.T) {
	if f := parsePHPShieldLine(""); f != nil {
		t.Error("empty should return nil")
	}
}

func TestParsePHPShieldLineNoBracket(t *testing.T) {
	if f := parsePHPShieldLine("no timestamp bracket"); f != nil {
		t.Error("no bracket should return nil")
	}
}

func TestParsePHPShieldLogLineWrapper(t *testing.T) {
	line := `[2026-04-12 10:00:00] BLOCK_PATH ip=1.2.3.4 script=/tmp/x.php`
	findings := parsePHPShieldLogLine(line, nil)
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

func TestParsePHPShieldLogLineWrapperNil(t *testing.T) {
	findings := parsePHPShieldLogLine("", nil)
	if findings != nil {
		t.Errorf("empty should return nil, got %v", findings)
	}
}

func TestProcessPHPShieldEventPacketArchivesAndEmits(t *testing.T) {
	dir := t.TempDir()
	line := `[2026-04-12 10:00:00] BLOCK_PATH ip=203.0.113.5 script=/tmp/evil.php details=blocked`
	archive := filepath.Join(dir, "events.log")
	alerts := make(chan alert.Finding, 1)
	processed, err := processPHPShieldEventPacket([]byte(line+"\n"), archive, &config.Config{}, alerts)
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Fatal("valid event was not processed")
	}
	archived, err := os.ReadFile(archive) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if string(archived) != line+"\n" {
		t.Fatalf("archive = %q, want %q", archived, line+"\n")
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("archive mode = %o, want 600", got)
	}
	select {
	case finding := <-alerts:
		if finding.Check != "php_shield_block" {
			t.Fatalf("finding check = %q", finding.Check)
		}
	default:
		t.Fatal("event did not emit a finding")
	}
}

func TestListenPHPShieldEventSocketRejectsPlantedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	if err := os.WriteFile(path, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := listenPHPShieldEventSocket(path)
	if err == nil || listener != nil {
		t.Fatalf("regular socket path accepted: listener=%v error=%v", listener, err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "planted" {
		t.Fatalf("planted path was modified: data=%q error=%v", data, readErr)
	}
}

func TestProcessPHPShieldEventPacketRejectsUntrustedRecords(t *testing.T) {
	dir := t.TempDir()
	valid := `[2026-04-12 10:00:00] BLOCK_PATH ip=1.2.3.4 script=/tmp/x.php`
	archive := filepath.Join(dir, "events.log")
	for name, packet := range map[string][]byte{
		"empty":     nil,
		"multiline": []byte(valid + "\n" + valid + "\n"),
		"unknown":   []byte(`[2026-04-12 10:00:00] UNKNOWN ip=1.2.3.4`),
		"oversized": make([]byte, phpEventMaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			alerts := make(chan alert.Finding, 1)
			processed, err := processPHPShieldEventPacket(packet, archive, &config.Config{}, alerts)
			if err != nil || processed || len(alerts) != 0 {
				t.Fatalf("processed=%t alerts=%d error=%v, want rejected packet", processed, len(alerts), err)
			}
		})
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("rejected records created archive: %v", err)
	}
}

func TestProcessPHPShieldEventPacketEmitsWhenArchiveUnavailable(t *testing.T) {
	dir := t.TempDir()
	line := `[2026-04-12 10:00:00] EVAL_FATAL ip=1.2.3.4 script=/tmp/x.php`
	archive := filepath.Join(dir, "missing", "events.log")
	alerts := make(chan alert.Finding, 1)
	processed, err := processPHPShieldEventPacket([]byte(line), archive, &config.Config{}, alerts)
	if err == nil || !processed {
		t.Fatalf("processed=%t error=%v, want emitted event plus archive error", processed, err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d, want detection preserved despite archive error", len(alerts))
	}
}

func TestAppendPHPShieldEventArchiveRejectsSymlinkAndCapsGrowth(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "events-link.log")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if archived, err := appendPHPShieldEventArchive(symlink, "event"); err == nil || archived {
		t.Fatalf("symlink archive accepted: archived=%t error=%v", archived, err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged" {
		t.Fatalf("symlink target changed: %q, %v", data, err)
	}

	hardlink := filepath.Join(dir, "events-hardlink.log")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if archived, err := appendPHPShieldEventArchive(hardlink, "event"); err == nil || archived {
		t.Fatalf("hard-linked archive accepted: archived=%t error=%v", archived, err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged" {
		t.Fatalf("hard-link target changed: %q, %v", data, err)
	}

	archive := filepath.Join(dir, "events.log")
	f, err := os.Create(archive) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(phpEventArchiveMaxBytes); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if archived, err := appendPHPShieldEventArchive(archive, "event"); !errors.Is(err, errPHPEventArchiveFull) || archived {
		t.Fatalf("full archive result: archived=%t error=%v, want size-cap error", archived, err)
	}
}

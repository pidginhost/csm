package daemon

import (
	"testing"
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

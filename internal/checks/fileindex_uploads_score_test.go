package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestScorePHPUploadSeverityBenignClassFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "class-pxl-breadcrumb.php")
	body := `<?php

class PxlBreadcrumb_Widget extends Pxltheme_Core_Widget_Base{
    protected $name = 'pxl_breadcrumb';
    protected $title = 'PXL Breadcrumb';
    protected $icon = 'eicon-navigation-horizontal';
    protected $categories = array( 'pxltheme-core' );
    protected $params = '{"sections":[]}';
    protected $styles = array();
    protected $scripts = array();
}
`
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scorePHPUploadSeverity(target); got != alert.Warning {
		t.Errorf("benign class file -> got %v, want Warning", got)
	}
}

func TestScorePHPUploadSeverityObfuscatedKeepsHigh(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.php")
	body := `<?php
eval(base64_decode("ZWNobyAxOw=="));
`
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scorePHPUploadSeverity(target); got != alert.High {
		t.Errorf("eval+base64 -> got %v, want High", got)
	}
}

func TestScorePHPUploadSeverityShellWithRequestSameLineKeepsHigh(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "y.php")
	body := `<?php
$out = system($_POST['cmd']);
`
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scorePHPUploadSeverity(target); got != alert.High {
		t.Errorf("shell+request same line -> got %v, want High", got)
	}
}

func TestScorePHPUploadSeverityUnreadableKeepsHigh(t *testing.T) {
	// Missing path -> analyzePHPContent returns severity=-1 because Open fails.
	// Fail-closed: alerting path stays High when we cannot inspect content.
	if got := scorePHPUploadSeverity("/nonexistent/path/that/does/not/exist.php"); got != alert.High {
		t.Errorf("unreadable -> got %v, want High (fail-closed)", got)
	}
}

func TestScorePHPUploadSeverityEmptyFileKeepsHigh(t *testing.T) {
	// Zero-byte PHP in uploads: cannot prove benign -> fail closed.
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.php")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scorePHPUploadSeverity(target); got != alert.High {
		t.Errorf("empty file -> got %v, want High (fail-closed)", got)
	}
}

package store

import (
	"testing"
	"time"
)

func TestHardeningReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Load with no saved report — should return zero-value
	report, err := db.LoadHardeningReport()
	if err != nil {
		t.Fatal(err)
	}
	if report.Results != nil {
		t.Fatalf("expected nil results, got %d", len(report.Results))
	}
	if report.Score != 0 || report.Total != 0 {
		t.Fatalf("expected 0/0, got %d/%d", report.Score, report.Total)
	}

	// Save a report
	saved := &AuditReport{
		Timestamp:  time.Now().Truncate(time.Second),
		ServerType: "cpanel",
		Results: []AuditResult{
			{Category: "ssh", Name: "ssh_port", Title: "SSH Port", Status: "pass", Message: "ok"},
			{Category: "ssh", Name: "ssh_password_auth", Title: "SSH PasswordAuth", Status: "fail", Message: "bad", Fix: "fix it"},
		},
		Score: 1,
		Total: 2,
	}
	if err := db.SaveHardeningReport(saved); err != nil {
		t.Fatal(err)
	}

	// Load it back
	loaded, err := db.LoadHardeningReport()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerType != "cpanel" {
		t.Fatalf("expected cpanel, got %s", loaded.ServerType)
	}
	if loaded.Score != 1 || loaded.Total != 2 {
		t.Fatalf("expected 1/2, got %d/%d", loaded.Score, loaded.Total)
	}
	if len(loaded.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(loaded.Results))
	}
	if loaded.Results[1].Fix != "fix it" {
		t.Fatalf("expected 'fix it', got %q", loaded.Results[1].Fix)
	}
}

func TestHardeningReportOverwrite(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	r1 := &AuditReport{Timestamp: time.Now(), ServerType: "bare", Score: 5, Total: 10}
	r2 := &AuditReport{Timestamp: time.Now(), ServerType: "cpanel", Score: 8, Total: 10}

	_ = db.SaveHardeningReport(r1)
	_ = db.SaveHardeningReport(r2)

	loaded, _ := db.LoadHardeningReport()
	if loaded.ServerType != "cpanel" || loaded.Score != 8 {
		t.Fatalf("expected overwritten report, got type=%s score=%d", loaded.ServerType, loaded.Score)
	}
}

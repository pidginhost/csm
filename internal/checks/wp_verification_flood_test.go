package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// recordWPVerificationFailures drives two cycles so every install reaches the
// persistent-failure threshold without going through wp-cli.
func recordWPVerificationFailures(t *testing.T, db *store.DB, reasons map[string]string, account string) {
	t.Helper()
	paths := make(map[string]string, len(reasons))
	results := make(map[string]store.WPVerificationResult, len(reasons))
	for path, reason := range reasons {
		paths[path] = account
		results[path] = store.WPVerificationResult{State: "unverified", Reason: reason}
	}
	at := time.Now()
	for cycle := range 2 {
		if err := db.UpdateWPVerification("core", at.Add(time.Duration(cycle)*time.Hour), "", paths, results, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWPVerificationCollapsesHostWideFailures(t *testing.T) {
	db := setupPluginStore(t)
	reasons := make(map[string]string, 40)
	for i := range 40 {
		reasons[fmt.Sprintf("/home/alice/site%02d", i)] = "wp-cli executable is unavailable"
	}
	recordWPVerificationFailures(t, db, reasons, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 1 {
		t.Fatalf("one host-wide cause produced %d alerts, exhausting the hourly alert budget", len(findings))
	}
	f := findings[0]
	if f.Check != "wp_core_unverified" || f.Severity != alert.Warning {
		t.Fatalf("collapsed coverage gap changed identity: %+v", f)
	}
	if !strings.Contains(f.Details, "40") || !strings.Contains(f.Details, "wp-cli executable is unavailable") {
		t.Fatalf("collapsed finding hides the scale or the cause: %+v", f)
	}
	if !strings.Contains(f.Details, "/home/alice/site00") || !strings.Contains(f.Details, "more") {
		t.Fatalf("collapsed finding names no examples and no remainder: %+v", f)
	}
}

func TestWPVerificationNamesEachInstallationBelowTheCap(t *testing.T) {
	db := setupPluginStore(t)
	recordWPVerificationFailures(t, db, map[string]string{
		"/home/alice/one": "wp-cli timed out",
		"/home/alice/two": "wp-cli timed out",
	}, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 2 {
		t.Fatalf("a handful of failures should still name each installation: %+v", findings)
	}
	for _, f := range findings {
		if f.FilePath == "" || !strings.Contains(f.Message, f.FilePath) {
			t.Fatalf("per-installation finding lost its path: %+v", f)
		}
	}
}

func TestWPVerificationCollapsesEachCauseSeparately(t *testing.T) {
	db := setupPluginStore(t)
	reasons := make(map[string]string, 40)
	for i := range 40 {
		reason := "wp-cli timed out"
		if i%2 == 0 {
			reason = "WordPress could not connect to its database"
		}
		reasons[fmt.Sprintf("/home/alice/site%02d", i)] = reason
	}
	recordWPVerificationFailures(t, db, reasons, "alice")

	findings := wpVerificationFindings(context.Background(), db, "core", "wp_core_verification", nil)
	if len(findings) != 2 {
		t.Fatalf("distinct causes must not share one alert: %+v", findings)
	}
	if findings[0].Key() == findings[1].Key() {
		t.Fatalf("collapsed causes share a dedup identity: %+v", findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Details, "20") {
			t.Fatalf("collapsed cause hides its count: %+v", f)
		}
	}
}

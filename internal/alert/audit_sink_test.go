package alert

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewAuditEventCarriesSchemaVersion(t *testing.T) {
	f := Finding{
		Severity:  Critical,
		Check:     "webshell",
		Message:   "boom",
		FilePath:  "/var/www/x.php",
		Timestamp: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
	}
	ev := NewAuditEvent("host.example", f)
	if ev.V != AuditSchemaVersion {
		t.Errorf("V = %d, want %d", ev.V, AuditSchemaVersion)
	}
	if ev.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", ev.Severity)
	}
	if ev.Hostname != "host.example" {
		t.Errorf("Hostname = %q", ev.Hostname)
	}
	if ev.Check != "webshell" || ev.FilePath != "/var/www/x.php" {
		t.Errorf("Check/FilePath wrong: %+v", ev)
	}
	if ev.FindingID == "" || len(ev.FindingID) != 16 {
		t.Errorf("FindingID = %q, want 16 hex chars", ev.FindingID)
	}
}

func TestMakeFindingIDDeterministic(t *testing.T) {
	f := Finding{
		Severity:  Warning,
		Check:     "x",
		Message:   "y",
		Timestamp: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
	}
	id1 := makeFindingID(f)
	id2 := makeFindingID(f)
	if id1 != id2 {
		t.Errorf("non-deterministic: %s vs %s", id1, id2)
	}
}

func TestMakeFindingIDChangesWithEachField(t *testing.T) {
	base := Finding{
		Severity:  Warning,
		Check:     "c",
		Message:   "m",
		FilePath:  "/p",
		Timestamp: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
	}
	id := makeFindingID(base)

	mutations := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"check", func(f *Finding) { f.Check = "different" }},
		{"message", func(f *Finding) { f.Message = "different" }},
		{"severity", func(f *Finding) { f.Severity = Critical }},
		{"filepath", func(f *Finding) { f.FilePath = "/different" }},
		{"timestamp", func(f *Finding) { f.Timestamp = f.Timestamp.Add(time.Second) }},
	}
	for _, m := range mutations {
		f := base
		m.mutate(&f)
		got := makeFindingID(f)
		if got == id {
			t.Errorf("ID unchanged after mutating %s", m.name)
		}
	}
}

func TestAuditEventJSONShape(t *testing.T) {
	f := Finding{
		Severity:  High,
		Check:     "modsec_block",
		Message:   "rule 949110 triggered",
		FilePath:  "",
		Timestamp: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
	}
	ev := NewAuditEvent("host.example", f)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	requiredKeys := []string{"v", "ts", "finding_id", "severity", "check", "message", "hostname"}
	for _, k := range requiredKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("key %q missing in JSON: %s", k, raw)
		}
	}
	// Empty FilePath/Details must be omitted.
	if _, ok := got["file_path"]; ok {
		t.Errorf("file_path should be omitted when empty: %s", raw)
	}
	if _, ok := got["details"]; ok {
		t.Errorf("details should be omitted when empty: %s", raw)
	}
}

package emailav

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestSpool(t *testing.T, msgID string) (spoolDir string) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, msgID+"-H"), []byte("test header data"), 0644)
	os.WriteFile(filepath.Join(dir, msgID+"-D"), []byte("test body data"), 0644)
	return dir
}

func TestQuarantineMessage(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	q := NewQuarantine(qDir)
	result := &ScanResult{
		MessageID: msgID,
		Infected:  true,
		Findings:  []Finding{{Filename: "test.exe", Engine: "clamav", Signature: "Win.Trojan.Test", Severity: "critical"}},
		ScannedAt: time.Now(),
	}
	envelope := QuarantineEnvelope{
		From:      "attacker@evil.com",
		To:        []string{"user@domain.com"},
		Subject:   "Test malware",
		Direction: "inbound",
	}

	err := q.QuarantineMessage(msgID, spoolDir, result, envelope)
	if err != nil {
		t.Fatalf("QuarantineMessage: %v", err)
	}

	// Verify spool files moved
	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-H")); !os.IsNotExist(err) {
		t.Error("spool -H file should have been moved")
	}
	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-D")); !os.IsNotExist(err) {
		t.Error("spool -D file should have been moved")
	}

	// Verify quarantine directory created
	msgDir := filepath.Join(qDir, msgID)
	if _, err := os.Stat(filepath.Join(msgDir, msgID+"-H")); err != nil {
		t.Errorf("quarantine -H file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(msgDir, msgID+"-D")); err != nil {
		t.Errorf("quarantine -D file missing: %v", err)
	}

	// Verify metadata
	metaData, err := os.ReadFile(filepath.Join(msgDir, "metadata.json"))
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	var meta QuarantineMetadata
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("parsing metadata: %v", err)
	}
	if meta.MessageID != msgID {
		t.Errorf("MessageID = %q, want %q", meta.MessageID, msgID)
	}
	if meta.From != "attacker@evil.com" {
		t.Errorf("From = %q, want %q", meta.From, "attacker@evil.com")
	}
}

func TestListMessages(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)

	// Quarantine two messages
	for _, id := range []string{"msg001-aaaaaa-AA", "msg002-bbbbbb-BB"} {
		spoolDir := setupTestSpool(t, id)
		result := &ScanResult{MessageID: id, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
		env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}
		if err := q.QuarantineMessage(id, spoolDir, result, env); err != nil {
			t.Fatalf("QuarantineMessage(%s): %v", id, err)
		}
	}

	msgs, err := q.ListMessages()
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("ListMessages = %d, want 2", len(msgs))
	}
}

func TestGetMessage(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	result := &ScanResult{MessageID: msgID, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
	env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}
	q.QuarantineMessage(msgID, spoolDir, result, env)

	msg, err := q.GetMessage(msgID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if msg.MessageID != msgID {
		t.Errorf("MessageID = %q, want %q", msg.MessageID, msgID)
	}
}

func TestReleaseMessage(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	result := &ScanResult{MessageID: msgID, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
	env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}
	q.QuarantineMessage(msgID, spoolDir, result, env)

	err := q.ReleaseMessage(msgID)
	if err != nil {
		t.Fatalf("ReleaseMessage: %v", err)
	}

	// Verify files moved back to spool
	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-H")); err != nil {
		t.Errorf("spool -H file should be restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-D")); err != nil {
		t.Errorf("spool -D file should be restored: %v", err)
	}

	// Verify quarantine directory removed
	if _, err := os.Stat(filepath.Join(qDir, msgID)); !os.IsNotExist(err) {
		t.Error("quarantine directory should be removed after release")
	}
}

func TestDeleteMessage(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	result := &ScanResult{MessageID: msgID, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
	env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}
	q.QuarantineMessage(msgID, spoolDir, result, env)

	err := q.DeleteMessage(msgID)
	if err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}

	if _, err := os.Stat(filepath.Join(qDir, msgID)); !os.IsNotExist(err) {
		t.Error("quarantine directory should be removed after delete")
	}
}

func TestCleanExpired(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	result := &ScanResult{MessageID: msgID, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
	env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}
	q.QuarantineMessage(msgID, spoolDir, result, env)

	// Backdate the metadata
	metaPath := filepath.Join(qDir, msgID, "metadata.json")
	metaData, _ := os.ReadFile(metaPath)
	var meta QuarantineMetadata
	json.Unmarshal(metaData, &meta)
	meta.QuarantinedAt = time.Now().Add(-31 * 24 * time.Hour) // 31 days ago
	updated, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(metaPath, updated, 0600)

	cleaned, err := q.CleanExpired(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("CleanExpired = %d, want 1", cleaned)
	}

	if _, err := os.Stat(filepath.Join(qDir, msgID)); !os.IsNotExist(err) {
		t.Error("expired quarantine should be cleaned")
	}
}

func TestQuarantineMessageRollsBackOnMetadataWriteFailure(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine", "email")
	q := NewQuarantine(qDir)
	msgID := "2jKPFm-000abc-1X"
	spoolDir := setupTestSpool(t, msgID)

	msgDir := filepath.Join(qDir, msgID)
	if err := os.MkdirAll(filepath.Join(msgDir, "metadata.json"), 0700); err != nil {
		t.Fatalf("creating blocking metadata dir: %v", err)
	}

	result := &ScanResult{MessageID: msgID, Infected: true, Findings: []Finding{{Filename: "f.exe", Engine: "clamav", Signature: "Sig", Severity: "critical"}}}
	env := QuarantineEnvelope{From: "a@b.com", To: []string{"c@d.com"}, Subject: "test", Direction: "inbound"}

	if err := q.QuarantineMessage(msgID, spoolDir, result, env); err == nil {
		t.Fatal("QuarantineMessage should fail when metadata.json is not writable")
	}

	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-H")); err != nil {
		t.Errorf("spool -H file should be restored after rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, msgID+"-D")); err != nil {
		t.Errorf("spool -D file should be restored after rollback: %v", err)
	}
}

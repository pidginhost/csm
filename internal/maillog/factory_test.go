package maillog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestFactory_AutoFallsBackToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maillog")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(config.MailLogsConfig{Source: "auto", File: path}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*FileReader); !ok {
		t.Fatalf("expected FileReader, got %T", r)
	}
}

func TestFactory_ExplicitJournalReturnsJournalReaderOrError(t *testing.T) {
	r, err := New(config.MailLogsConfig{Source: "journal", Units: []string{"postfix"}}, "")
	// On default builds, journal stub returns ErrJournalUnsupported on Run.
	// The factory itself succeeds (returns *JournalReader).
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*JournalReader); !ok {
		t.Fatalf("expected JournalReader, got %T", r)
	}
}

func TestFactory_FileWithMissingFileErrors(t *testing.T) {
	_, err := New(config.MailLogsConfig{Source: "file", File: "/no/such/file"}, "")
	if err == nil {
		t.Fatal("expected error when file source and file missing")
	}
}

func TestFactory_AutoMissingFileFallsBackToJournal(t *testing.T) {
	r, err := New(config.MailLogsConfig{
		Source: "auto",
		File:   "/no/such/file",
		Units:  []string{"postfix"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*JournalReader); !ok {
		t.Fatalf("expected fallback to JournalReader, got %T", r)
	}
}

func TestFactory_AutoMissingFileNoUnitsErrors(t *testing.T) {
	_, err := New(config.MailLogsConfig{
		Source: "auto",
		File:   "/no/such/file",
		// no units
	}, "")
	if err == nil {
		t.Fatal("expected error when both file missing and no journal units")
	}
}

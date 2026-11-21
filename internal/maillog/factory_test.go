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
	r, err := New(config.MailLogsConfig{Source: "auto", File: path}, "", NewQueue())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*FileReader); !ok {
		t.Fatalf("expected FileReader, got %T", r)
	}
}

func TestFactory_ExplicitJournalReturnsJournalReaderOrError(t *testing.T) {
	r, err := New(config.MailLogsConfig{Source: "journal", Units: []string{"postfix"}}, "", NewQueue())
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
	_, err := New(config.MailLogsConfig{Source: "file", File: "/no/such/file"}, "", NewQueue())
	if err == nil {
		t.Fatal("expected error when file source and file missing")
	}
}

func TestFactory_AutoMissingFileFallsBackToJournal(t *testing.T) {
	r, err := New(config.MailLogsConfig{
		Source: "auto",
		File:   "/no/such/file",
		Units:  []string{"postfix"},
	}, "", NewQueue())
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
	}, "", NewQueue())
	if err == nil {
		t.Fatal("expected error when both file missing and no journal units")
	}
}

func TestUsesJournalIncludesMissingFileFallback(t *testing.T) {
	withJournalUnusable(t)
	cfg := config.MailLogsConfig{Source: "auto", File: filepath.Join(t.TempDir(), "missing"), Units: []string{"postfix"}}
	r, err := New(cfg, "", NewQueue())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*JournalReader); !ok {
		t.Fatalf("expected journal fallback, got %T", r)
	}
	if journal, err := UsesJournal(cfg, ""); err != nil || !journal {
		t.Fatal("doctor reports a file while the daemon selects the journal")
	}
}

// Selection must match the actual reader, including platform defaults and
// errors, even when the journal cannot receive syslog on this host.
func TestUsesJournalMatchesFactory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name, source, path, fallback string
		usable, units, journal, bad  bool
	}{
		{"auto prefers usable journal", "auto", file, "", true, true, true, false},
		{"auto platform file", "auto", "", file, false, true, false, false},
		{"auto explicit file", "auto", file, missing, false, true, false, false},
		{"auto missing explicit overrides default", "auto", missing, file, false, true, true, false},
		{"auto missing platform file", "auto", "", missing, false, true, true, false},
		{"auto missing without units", "auto", "", missing, false, false, false, true},
		{"file despite usable journal", "file", file, "", true, true, false, false},
		{"file platform default", "file", "", file, false, false, false, false},
		{"file missing", "file", missing, file, true, true, false, true},
		{"journal without syslog", "journal", file, "", false, true, true, false},
		{"journal missing units", "journal", file, "", true, false, false, true},
		{"empty source", "", file, "", true, true, false, true},
		{"unknown source", "unknown", file, "", true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usableJournalHost(t, tc.usable, tc.usable, true)
			cfg := config.MailLogsConfig{Source: tc.source, File: tc.path}
			if tc.units {
				cfg.Units = []string{"postfix", "dovecot"}
			}
			journal, err := UsesJournal(cfg, tc.fallback)
			if (err != nil) != tc.bad || journal != tc.journal {
				t.Fatalf("UsesJournal = %v, %v; want journal=%v, error=%v", journal, err, tc.journal, tc.bad)
			}
			r, readerErr := New(cfg, tc.fallback, NewQueue())
			if tc.bad {
				if readerErr == nil || readerErr.Error() != err.Error() || r != nil {
					t.Fatalf("reader = %T, %v; want nil, %v", r, readerErr, err)
				}
				return
			}
			if readerErr != nil {
				t.Fatal(readerErr)
			}
			_, isJournal := r.(*JournalReader)
			if isJournal != tc.journal {
				t.Fatalf("reader = %T; want journal=%v", r, tc.journal)
			}
			if !isJournal {
				f, ok := r.(*FileReader)
				if !ok || f.path != file {
					t.Fatalf("reader = %#v; want file %q", r, file)
				}
			}
		})
	}
}

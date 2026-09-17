package reporting

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolterrors "go.etcd.io/bbolt/errors"
)

func TestSpoolerEnqueueReturnsPersistenceFailure(t *testing.T) {
	spool, err := NewSpool(filepath.Join(t.TempDir(), "reports.db"), "reports", 3)
	if err != nil {
		t.Fatal(err)
	}
	spooler := NewSpooler(spool, nil, []Target{{Name: "first"}, {Name: "second"}}, time.Minute)
	if closeErr := spool.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	var reporter Reporter = spooler
	err = reporter.Enqueue(Report{IP: "192.0.2.1", FirstSeen: time.Now(), LastSeen: time.Now()})
	if !errors.Is(err, bolterrors.ErrDatabaseNotOpen) || !strings.Contains(err.Error(), "first") || !strings.Contains(err.Error(), "second") {
		t.Fatalf("persistence failure was concealed: %v", err)
	}
}

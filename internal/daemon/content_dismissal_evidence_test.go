package daemon

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func TestInitialContentRevocationPreservesEvidence(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(nil)
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	alert.CloseAuditSinks()
	t.Cleanup(alert.CloseAuditSinks)
	cfg.Alerts.AuditLog.File.Enabled = true
	cfg.Alerts.AuditLog.File.Path = filepath.Join(t.TempDir(), "audit.jsonl")

	a := daemonContentFinding(strings.Repeat("a", 64))
	b := daemonContentFinding(strings.Repeat("b", 64))
	unknown, carried := a, a
	unknown.ContentSHA256 = ""
	carried.ScanCarryForward = true
	batch := []alert.Finding{a, unknown, carried, b}
	want := make(map[string]int)
	for i := range batch {
		batch[i].Timestamp = time.Date(2026, 1, 2, 10, i, 0, 0, time.UTC)
		want[alert.FindingID(batch[i])]++
	}
	dismissListed(d, a)

	d.respondToInitialScan(cfg, batch)

	history, total := d.store.ReadHistory(10, 0)
	if total != len(batch) {
		t.Errorf("history has %d observations, want %d", total, len(batch))
	}
	got := make(map[string]int)
	for _, f := range history {
		got[alert.FindingID(f)]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("history observations = %v, want %v", got, want)
	}

	alert.CloseAuditSinks()
	file, err := os.Open(cfg.Alerts.AuditLog.File.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got = make(map[string]int)
	decoder := json.NewDecoder(file)
	for {
		var event alert.AuditEvent
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		got[event.FindingID]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("audit observations = %v, want %v", got, want)
	}
}

func TestInitialContentRevocationRespondsToFreshContent(t *testing.T) {
	for _, recorded := range []string{"", strings.Repeat("a", 64)} {
		name := "known"
		if recorded == "" {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			cfg, hook := emailRepeatSetup(t)
			d := openRepeatDaemon(t, cfg)
			calls := stubQueueCompanionSweeps(t)
			dismissListed(d, daemonContentFinding(recorded))
			a := daemonContentFinding(strings.Repeat("a", 64))
			b := daemonContentFinding(strings.Repeat("b", 64))
			unknown, carried := a, b
			unknown.ContentSHA256 = ""
			carried.ScanCarryForward = true

			fresh, fixed := d.respondToInitialScan(cfg, []alert.Finding{unknown, carried, a, b})

			if len(fresh) != 1 || fresh[0].ContentSHA256 != b.ContentSHA256 || fresh[0].ScanCarryForward {
				t.Fatalf("new findings = %+v, want only fresh changed content", fresh)
			}
			if len(fixed) != 0 {
				t.Errorf("permission fixes = %v, want none for a content finding", fixed)
			}
			if len(*calls) != 1 || len((*calls)[0]) != 1 || (*calls)[0][0].ContentSHA256 != b.ContentSHA256 {
				t.Fatalf("response findings = %+v, want only fresh changed content", *calls)
			}
			if got := hook.count("webshell_generic"); got != 1 {
				t.Errorf("webhooks = %d, want one new-content alert", got)
			}
			if d.store.Acknowledged(b) {
				t.Fatal("changed content is still dismissed")
			}
		})
	}
}

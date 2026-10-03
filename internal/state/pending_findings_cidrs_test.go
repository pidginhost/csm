package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Subnets ride the public cidrs key now; the parked record keeps writing the
// storage-only copy so a daemon rolled back after a restart still replays
// them, and replay accepts either key.
func TestPendingFindingsReplayCIDRsFromEitherKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	crawl := alert.Finding{Check: "http_asn_crawl", Message: "crawl", CIDRs: []string{"198.51.100.0/24"}, Timestamp: time.Unix(1790000000, 0)}
	if appendErr := st.AppendPendingFindings([]alert.Finding{crawl}); appendErr != nil {
		t.Fatal(appendErr)
	}
	raw, err := os.ReadFile(filepath.Join(st.path, pendingFindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	var parked []struct {
		CIDRs         []string `json:"cidrs"`
		ResponseCIDRs []string `json:"response_cidrs"`
	}
	if decodeErr := json.Unmarshal(raw, &parked); decodeErr != nil || len(parked) != 1 ||
		!reflect.DeepEqual(parked[0].CIDRs, crawl.CIDRs) || !reflect.DeepEqual(parked[0].ResponseCIDRs, crawl.CIDRs) {
		t.Fatalf("parked record %s (error %v), want the public and the storage-only subnets", raw, decodeErr)
	}
	for name, record := range map[string]string{
		"public key only":       `[{"check":"http_asn_crawl","message":"crawl","timestamp":"2026-10-02T12:00:00Z","cidrs":["203.0.113.0/24"]}]`,
		"storage-only key only": `[{"check":"http_asn_crawl","message":"crawl","timestamp":"2026-10-02T12:00:00Z","response_cidrs":["203.0.113.0/24"]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			other, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if writeErr := os.WriteFile(filepath.Join(dir, pendingFindingsFile), []byte(record), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			got, err := other.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || !reflect.DeepEqual(got[0].CIDRs, []string{"203.0.113.0/24"}) {
				t.Fatalf("replayed %+v, want the subnet", got)
			}
		})
	}
}

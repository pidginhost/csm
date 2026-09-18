package webui

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func readUIScript(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("../../ui/static/js/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// Selecting more files than one request may carry used to send them all at
// once and fail the whole delete. The pages must split the selection into
// batches no larger than the server accepts.
func TestQuarantineBulkDeleteSendsBatchesWithinServerLimit(t *testing.T) {
	shared := readUIScript(t, "csrf.js")
	for _, fragment := range []string{
		fmt.Sprintf("CSM.QUARANTINE_BULK_MAX = %d;", quarantineBulkDeleteMax),
		"CSM.postBatches = function(url, items, size, body, onBatch) {",
	} {
		if !strings.Contains(shared, fragment) {
			t.Fatalf("csrf.js missing %q", fragment)
		}
	}
	for _, page := range []string{"quarantine.js", "cleanup-history.js"} {
		src := readUIScript(t, page)
		if strings.Contains(src, "CSM.post('/api/v1/quarantine/bulk-delete'") {
			t.Errorf("%s sends the whole selection in one bulk-delete request", page)
		}
		if !strings.Contains(src, "CSM.postBatches('/api/v1/quarantine/bulk-delete', ids, CSM.QUARANTINE_BULK_MAX,") {
			t.Errorf("%s does not batch bulk-delete within the server limit", page)
		}
	}
}

// Threat bulk actions return one undo token per request, so they cannot be
// split into batches behind a single undo. The page checks the server limit
// before sending instead of failing with the raw server error.
func TestThreatBulkActionsCheckServerLimitFirst(t *testing.T) {
	if want := fmt.Sprintf("CSM.THREAT_BULK_MAX = %d;", threatBulkActionMax); !strings.Contains(readUIScript(t, "csrf.js"), want) {
		t.Fatalf("csrf.js missing %q", want)
	}
	if got := strings.Count(readUIScript(t, "threat.js"), "ips.length > CSM.THREAT_BULK_MAX"); got != 2 {
		t.Fatalf("threat.js checks the bulk limit in %d places, want block and whitelist", got)
	}
}

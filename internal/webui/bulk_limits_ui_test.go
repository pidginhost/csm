package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestQuarantineMutationsStayLockedThroughRefresh(t *testing.T) {
	src := readUIScript(t, "quarantine.js")
	for _, fragment := range []string{
		"if (_quarMutationBusy) return Promise.resolve();",
		"_quarMutationBusy = true;",
		"_quarMutationBusy = false;",
		"onChange: syncQuarantineMutationButtons",
		"return CSM.get('/api/v1/quarantine')",
		"return CSM.postBatches('/api/v1/quarantine/bulk-delete'",
		"}).then(loadQuarantine);",
	} {
		if !strings.Contains(src, fragment) {
			t.Errorf("quarantine.js missing mutation guard fragment %q", fragment)
		}
	}
	if got := strings.Count(src, "return withQuarantineMutation(function()"); got != 3 {
		t.Errorf("quarantine.js guards %d mutations, want single restore, bulk restore and delete", got)
	}
}

func TestFindingsBulkActionsCheckBodyLimit(t *testing.T) {
	if want := fmt.Sprintf("CSM.FIX_BULK_BODY_MAX = %d;", bulkFixBodyMax); !strings.Contains(readUIScript(t, "csrf.js"), want) {
		t.Fatalf("csrf.js missing %q", want)
	}
	src := readUIScript(t, "findings.js")
	for _, fragment := range []string{
		"new Blob([JSON.stringify(payload)]).size > CSM.FIX_BULK_BODY_MAX",
		"var fixItems = bulkFixPayload(fixable);\n        if (!fixItems) return;\n        CSM.confirm(",
		"var quarItems = bulkFixPayload(items);\n        if (!quarItems) return;\n        CSM.confirm(",
	} {
		if !strings.Contains(src, fragment) {
			t.Errorf("findings.js missing request-size check %q", fragment)
		}
	}
}

func TestBulkFixRequestBodyBoundary(t *testing.T) {
	const prefix = `[{"check":"unsupported-test-check","details":"`
	const suffix = `"}]`
	for _, size := range []int{bulkFixBodyMax - 1, bulkFixBodyMax, bulkFixBodyMax + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
			w := httptest.NewRecorder()
			s := &Server{}
			s.apiBulkFix(w, httptest.NewRequest(http.MethodPost, "/api/v1/fix-bulk", strings.NewReader(body)))
			want := http.StatusOK
			if size > bulkFixBodyMax {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("body of %d bytes: status = %d, want %d", size, w.Code, want)
			}
		})
	}
}

func TestCleanupLocksRowRestoresDuringBulkDelete(t *testing.T) {
	src := readUIScript(t, "cleanup-history.js")
	for _, fragment := range []string{
		"if (fileMutationBusy) return Promise.resolve();",
		"fileMutationBusy = true;",
		"fileMutationBusy = false;",
		"btn.disabled = fileMutationBusy;",
		"return withFileBulkButtons(null, '', function()",
	} {
		if !strings.Contains(src, fragment) {
			t.Errorf("cleanup-history.js missing row restore guard %q", fragment)
		}
	}
}

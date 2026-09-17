package corpusgate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func Root(key string) (string, error) {
	root := os.Getenv(key)
	if root == "" && os.Getenv("CSM_CORPUS_REQUIRED") == "1" {
		return "", fmt.Errorf("required corpus variable %s is missing", key)
	}
	return root, nil
}

type Report struct {
	Engine           string         `json:"engine"`
	Scanned          int            `json:"scanned"`
	Hits             map[string]int `json:"hits"`
	Thresholds       map[string]int `json:"thresholds"`
	Statuses         map[string]int `json:"statuses,omitempty"`
	StatusThresholds map[string]int `json:"status_thresholds,omitempty"`
}

func (r Report) Validate() error {
	if r.Scanned <= 0 {
		return fmt.Errorf("%s scanned no files", r.Engine)
	}
	var bad []string
	for rule, count := range r.Hits {
		if count > r.Thresholds[rule] {
			bad = append(bad, fmt.Sprintf("%s=%d (maximum %d)", rule, count, r.Thresholds[rule]))
		}
	}
	for status, count := range r.Statuses {
		if status != "analyzed" && status != "not_candidate" && count > r.StatusThresholds[status] {
			bad = append(bad, fmt.Sprintf("status %s=%d (maximum %d)", status, count, r.StatusThresholds[status]))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		return fmt.Errorf("%s corpus regressions: %s", r.Engine, strings.Join(bad, ", "))
	}
	return nil
}

// Save writes before validation, retaining evidence from failing gates too.
func (r Report) Save() error {
	dir := os.Getenv("CSM_CORPUS_REPORT_DIR")
	if dir == "" {
		if os.Getenv("CSM_CORPUS_REQUIRED") == "1" {
			return fmt.Errorf("CSM_CORPUS_REPORT_DIR is required")
		}
		return nil
	}
	thresholds := make(map[string]int, len(r.Hits))
	for rule := range r.Hits {
		thresholds[rule] = r.Thresholds[rule]
	}
	for rule, limit := range r.Thresholds {
		thresholds[rule] = limit
	}
	r.Thresholds = thresholds
	return WriteJSON(filepath.Join(dir, r.Engine+".json"), r)
}

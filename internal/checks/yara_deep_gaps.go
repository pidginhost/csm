package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// maxYARAGapPaths bounds the exact-path set a single run retains. Past it the
// count keeps rising but the paths are no longer authoritative, which forces
// the run partial rather than letting a purge clear a path it can no longer
// name.
const maxYARAGapPaths = 5000

const yaraGapExampleMaxBytes = 200

// yaraGapCollector records what a YARA deep scan walked but could not examine.
// It mirrors the PHP and JS taint collectors deliberately: those two consumers
// already distinguish a gap that names a file from one that loses an unknown
// range, and YARA reporting only a bare count is what made a permanently
// unreadable file indistinguishable from a lost subtree.
type yaraGapCollector struct {
	paths          map[string]struct{}
	byStatus       map[string]int
	example        map[string]string
	unknown        int
	unknownExample string
	pathsTruncated bool
}

func newYARAGapCollector() *yaraGapCollector {
	return &yaraGapCollector{
		paths:    map[string]struct{}{},
		byStatus: map[string]int{},
		example:  map[string]string{},
	}
}

// record notes one file the scan could not examine, under a status naming why.
func (g *yaraGapCollector) record(path, status string) {
	if _, retained := g.paths[path]; !retained {
		if len(g.paths) < maxYARAGapPaths {
			g.paths[path] = struct{}{}
		} else {
			// Keep counting; stop claiming the path set is complete.
			g.pathsTruncated = true
		}
	}
	g.byStatus[status]++
	if _, ok := g.example[status]; !ok {
		g.example[status] = sanitizeJSTaintDisplay(path, yaraGapExampleMaxBytes)
	}
}

// recordUnknownRange notes coverage lost over a range this walk cannot
// enumerate -- an unreadable directory, a failed Lstat that may hide a subtree.
// It deliberately records no path: claiming one would be false, and an unknown
// range has to suppress the purge for the whole owner.
func (g *yaraGapCollector) recordUnknownRange(detail string) {
	g.unknown++
	if g.unknownExample == "" {
		g.unknownExample = sanitizeJSTaintDisplay(detail, yaraGapExampleMaxBytes)
	}
}

// pathsIncomplete reports that this run cannot enumerate every gapped path, so
// its carry-forward set is not authoritative and the purge must be suppressed.
func (g *yaraGapCollector) pathsIncomplete() bool {
	return g.pathsTruncated || g.unknown > 0
}

func (g *yaraGapCollector) empty() bool { return len(g.byStatus) == 0 && g.unknown == 0 }

func (g *yaraGapCollector) hasPath(path string) bool {
	_, ok := g.paths[path]
	return ok
}

func (g *yaraGapCollector) finding() alert.Finding {
	total := 0
	statuses := make([]string, 0, len(g.byStatus))
	for status, n := range g.byStatus {
		total += n
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	parts := make([]string, 0, len(statuses)+2)
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%s=%d (example: %s)", status, g.byStatus[status], g.example[status]))
	}
	if g.unknown > 0 {
		parts = append(parts, fmt.Sprintf("unreadable-range=%d (example: %s)", g.unknown, g.unknownExample))
	}
	if g.pathsTruncated {
		parts = append(parts, fmt.Sprintf("exact paths retained for only the first %d", maxYARAGapPaths))
	}
	message := fmt.Sprintf("YARA deep scan could not inspect %d file(s)", total)
	if total == 0 {
		message = fmt.Sprintf("YARA deep scan could not cover %d location(s)", g.unknown)
	}
	return alert.Finding{
		Severity: alert.High,
		Check:    "yara_scan_incomplete",
		Message:  message,
		Details:  strings.Join(parts, "; "),
	}
}

// carryForwardYARAFindings keeps at most one prior finding per path this cycle
// could not examine. A run that covered everything else is eligible to replace
// the YARA finding set, so a file it could not read must have its existing
// finding re-emitted or the purge would clear a finding nothing disproved.
func carryForwardYARAFindings(prior []alert.Finding, gaps *yaraGapCollector) []alert.Finding {
	byPath := make(map[string]alert.Finding)
	for _, finding := range prior {
		if finding.Check != "yara_match_scheduled" || !gaps.hasPath(finding.FilePath) {
			continue
		}
		current, exists := byPath[finding.FilePath]
		if !exists || finding.Timestamp.After(current.Timestamp) ||
			(finding.Timestamp.Equal(current.Timestamp) && finding.Key() < current.Key()) {
			byPath[finding.FilePath] = finding
		}
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	carried := make([]alert.Finding, 0, len(paths))
	for _, path := range paths {
		carried = append(carried, byPath[path])
	}
	return carried
}

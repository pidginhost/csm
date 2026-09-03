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
	pathAliases    map[string]struct{}
	aliasesByPath  map[string][]string
	resolveAliases func(string) ([]string, bool)
	byStatus       map[string]int
	example        map[string]string
	unknown        int
	unknownExample string
	pathsTruncated bool
}

func newYARAGapCollector() *yaraGapCollector {
	return &yaraGapCollector{
		paths:         map[string]struct{}{},
		pathAliases:   map[string]struct{}{},
		aliasesByPath: map[string][]string{},
		byStatus:      map[string]int{},
		example:       map[string]string{},
	}
}

// record notes one file the scan could not examine, under a status naming why.
// It returns the aliases captured for an authoritative retained path so the
// atomic path-scoped purge uses exactly the same identity as carry-forward.
func (g *yaraGapCollector) record(path, status string) []string {
	var aliases []string
	if _, alreadyRetained := g.paths[path]; !alreadyRetained {
		if len(g.paths) < maxYARAGapPaths {
			stable := true
			if g.resolveAliases != nil {
				aliases, stable = g.resolveAliases(path)
			} else {
				// Must stay symmetric with hasPath, which queries by every
				// alias. Recording only the lexical spelling meant a finding
				// stored through a symlinked document root never matched its
				// own gap, and was purged for a file the scan never read.
				aliases = coveragePathAliases(path)
			}
			if !stable {
				g.recordUnknownRange(fmt.Sprintf("%s changed while its path identity was captured", path))
				g.byStatus[status]++
				if _, ok := g.example[status]; !ok {
					g.example[status] = sanitizeJSTaintDisplay(path, yaraGapExampleMaxBytes)
				}
				return nil
			}
			g.paths[path] = struct{}{}
			g.aliasesByPath[path] = aliases
			for _, alias := range aliases {
				g.pathAliases[alias] = struct{}{}
			}
		} else {
			// Keep counting; stop claiming the path set is complete.
			g.pathsTruncated = true
		}
	} else {
		aliases = g.aliasesByPath[path]
	}
	g.byStatus[status]++
	if _, ok := g.example[status]; !ok {
		g.example[status] = sanitizeJSTaintDisplay(path, yaraGapExampleMaxBytes)
	}
	return aliases
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
	if _, ok := g.paths[path]; ok {
		return true
	}
	for _, alias := range coveragePathAliases(path) {
		if _, ok := g.pathAliases[alias]; ok {
			return true
		}
	}
	return false
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

// carryForwardYARAFindings keeps every distinct prior rule finding for paths
// this cycle could not examine. YARA can emit several rule matches for one
// file, so collapsing by path would silently retire all but one finding even
// though the scan formed no opinion about any of them. Duplicate snapshots of
// the same identity are collapsed by Key, with the newest snapshot winning.
func carryForwardYARAFindings(prior []alert.Finding, gaps *yaraGapCollector) []alert.Finding {
	byKey := make(map[string]alert.Finding)
	for _, finding := range prior {
		if finding.Check != "yara_match_scheduled" || !gaps.hasPath(finding.FilePath) {
			continue
		}
		key := finding.Key()
		current, exists := byKey[key]
		if !exists || finding.Timestamp.After(current.Timestamp) ||
			(finding.Timestamp.Equal(current.Timestamp) && finding.FilePath < current.FilePath) {
			byKey[key] = finding
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	carried := make([]alert.Finding, 0, len(keys))
	for _, key := range keys {
		finding := byKey[key]
		finding.ScanCarryForward = true
		carried = append(carried, finding)
	}
	return carried
}

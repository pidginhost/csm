package checks

import (
	"sort"

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
	gapPathSet
}

func newYARAGapCollector() *yaraGapCollector {
	// The default resolver must stay symmetric with hasPath, which queries by
	// every alias. Recording only the lexical spelling meant a finding stored
	// through a symlinked document root never matched its own gap, and was
	// purged for a file the scan never read.
	return &yaraGapCollector{gapPathSet: newGapPathSet(maxYARAGapPaths, yaraGapExampleMaxBytes,
		func(path string) ([]string, bool) { return coveragePathAliases(path), true })}
}

// record notes one file the scan could not examine, under a status naming why.
// It returns the aliases captured for an authoritative retained path so the
// atomic path-scoped purge uses exactly the same identity as carry-forward.
func (g *yaraGapCollector) record(path, status string) []string {
	return g.retain(path, status)
}

func (g *yaraGapCollector) finding() alert.Finding {
	return g.incompleteFinding(alert.High, "yara_scan_incomplete",
		"YARA deep scan could not inspect %d file(s)",
		"YARA deep scan could not cover %d location(s)")
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

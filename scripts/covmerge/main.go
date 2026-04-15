// covmerge merges two Go coverage profiles (primary first, secondary
// second). Unlike gocovmerge, when a single file's statement ranges
// don't match between the two profiles (typical when the secondary
// profile was generated against an older code revision), this tool
// keeps per-range matches from secondary and ignores the non-matching
// ones instead of dropping the whole file.
//
// Usage: covmerge primary.out secondary.out > merged.out
//
// The primary profile's statements are authoritative (structure and
// statement count). Secondary contributes hit counts only for ranges
// whose rangeKey appears in primary. Hit counts are summed per range.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

type entry struct {
	rangeKey string // "startLine.startCol,endLine.endCol"
	stmt     int
	hits     int
}

type profile struct {
	mode   string
	byFile map[string][]entry // file → entries, insertion order preserved
	order  []string           // file insertion order
}

func readProfile(path string) (*profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	p := &profile{byFile: make(map[string][]entry)}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "mode:") {
			p.mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
			continue
		}
		// Line format: "path/to/file.go:start.col,end.col numStmt count"
		// The path may contain colons on Windows, but Go coverage profiles
		// always emit forward slashes and the LAST colon separates range.
		colonIdx := strings.LastIndex(line, ":")
		if colonIdx < 0 {
			continue
		}
		file := line[:colonIdx]
		rest := line[colonIdx+1:]
		// rest: "start.col,end.col numStmt count"
		parts := strings.Fields(rest)
		if len(parts) != 3 {
			continue
		}
		var stmt, hits int
		if _, err := fmt.Sscan(parts[1], &stmt); err != nil {
			continue
		}
		if _, err := fmt.Sscan(parts[2], &hits); err != nil {
			continue
		}
		if _, seen := p.byFile[file]; !seen {
			p.order = append(p.order, file)
		}
		p.byFile[file] = append(p.byFile[file], entry{
			rangeKey: parts[0],
			stmt:     stmt,
			hits:     hits,
		})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	// Dedupe per file. `go test ./... -coverpkg=./internal/...` instruments
	// internal/* statements from every test binary, so the same statement
	// appears N times in the profile (once per binary). Aggregate by
	// rangeKey so subsequent merge steps work on unique statements.
	for file, entries := range p.byFile {
		p.byFile[file] = dedupeEntries(entries, p.mode)
	}
	return p, nil
}

// dedupeEntries collapses entries with the same rangeKey into one. For
// "set" mode any non-zero hit count means covered. For "atomic"/"count"
// modes hits are summed.
func dedupeEntries(entries []entry, mode string) []entry {
	if len(entries) == 0 {
		return entries
	}
	byRange := make(map[string]*entry, len(entries))
	order := make([]string, 0, len(entries))
	for i := range entries {
		k := entries[i].rangeKey
		if existing, ok := byRange[k]; ok {
			if mode == "set" {
				if entries[i].hits > 0 {
					existing.hits = 1
				}
			} else {
				existing.hits += entries[i].hits
			}
			continue
		}
		// Copy so subsequent mutations don't alias the input slice.
		e := entries[i]
		byRange[k] = &e
		order = append(order, k)
	}
	out := make([]entry, 0, len(order))
	for _, k := range order {
		out = append(out, *byRange[k])
	}
	return out
}

// rangesEqual returns true if two slices of entries cover exactly the
// same set of statement ranges (order-insensitive).
func rangesEqual(a, b []entry) bool {
	if len(a) != len(b) {
		return false
	}
	ak := make([]string, len(a))
	bk := make([]string, len(b))
	for i := range a {
		ak[i] = a[i].rangeKey
		bk[i] = b[i].rangeKey
	}
	sort.Strings(ak)
	sort.Strings(bk)
	for i := range ak {
		if ak[i] != bk[i] {
			return false
		}
	}
	return true
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: covmerge primary.out secondary.out > merged.out")
		os.Exit(2)
	}
	primary, err := readProfile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading primary: %v\n", err)
		os.Exit(1)
	}
	secondary, err := readProfile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading secondary: %v\n", err)
		os.Exit(1)
	}

	mode := primary.mode
	if mode == "" {
		mode = secondary.mode
	}
	if mode == "" {
		mode = "set"
	}

	// Merge per-file, per-range. Primary's statement set is authoritative;
	// secondary contributes hit counts only for ranges that still match.
	merged := make(map[string][]entry, len(primary.byFile))
	order := append([]string(nil), primary.order...)
	partialFiles := 0
	cleanFiles := 0

	for _, file := range primary.order {
		pEntries := primary.byFile[file]
		sEntries, inSecondary := secondary.byFile[file]
		if !inSecondary {
			merged[file] = pEntries
			continue
		}
		byRange := make(map[string]*entry, len(pEntries))
		for i := range pEntries {
			byRange[pEntries[i].rangeKey] = &pEntries[i]
		}
		matched, drifted := 0, 0
		for i := range sEntries {
			e, ok := byRange[sEntries[i].rangeKey]
			if !ok {
				drifted++
				continue
			}
			matched++
			if mode == "set" {
				if sEntries[i].hits > 0 || e.hits > 0 {
					e.hits = 1
				}
			} else {
				e.hits += sEntries[i].hits
			}
		}
		if drifted > 0 || matched < len(pEntries) {
			fmt.Fprintf(os.Stderr, "covmerge: %s: %d/%d ranges matched (%d secondary entries had no primary match)\n",
				file, matched, len(pEntries), drifted)
			partialFiles++
		} else {
			cleanFiles++
		}
		merged[file] = pEntries
	}

	// Include files that appear only in secondary.
	secondaryOnly := 0
	for _, file := range secondary.order {
		if _, seen := merged[file]; seen {
			continue
		}
		merged[file] = secondary.byFile[file]
		order = append(order, file)
		secondaryOnly++
	}

	fmt.Fprintf(os.Stderr, "covmerge: %d files merged cleanly, %d files partially merged (some drift), %d files from secondary only\n",
		cleanFiles, partialFiles, secondaryOnly)

	// Emit merged profile. Primary order first, then secondary-only files.
	out := bufio.NewWriter(os.Stdout)
	defer func() { _ = out.Flush() }()
	fmt.Fprintf(out, "mode: %s\n", mode)
	for _, file := range order {
		for _, e := range merged[file] {
			fmt.Fprintf(out, "%s:%s %d %d\n", file, e.rangeKey, e.stmt, e.hits)
		}
	}
}

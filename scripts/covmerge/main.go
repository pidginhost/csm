// covmerge merges two Go coverage profiles (primary first, secondary
// second). Unlike gocovmerge, when a single file's statement ranges
// don't match between the two profiles (typical when the secondary
// profile was generated against an older code revision), this tool
// drops that file from the secondary profile and continues instead
// of failing the whole merge.
//
// Usage: covmerge primary.out secondary.out > merged.out
//
// The primary profile's statements are authoritative. Secondary
// statements are only included when their ranges match primary's
// exactly (per file). Hit counts are summed for matching statements.
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
	return p, nil
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

	// Merge per-file.
	merged := make(map[string][]entry, len(primary.byFile))
	order := append([]string(nil), primary.order...)
	droppedFiles := 0
	mergedFiles := 0

	for _, file := range primary.order {
		pEntries := primary.byFile[file]
		sEntries, inSecondary := secondary.byFile[file]
		if !inSecondary {
			merged[file] = pEntries
			continue
		}
		if !rangesEqual(pEntries, sEntries) {
			// Drift - keep primary only, drop secondary's entries for this file.
			fmt.Fprintf(os.Stderr, "covmerge: dropping %s from secondary (statement ranges differ)\n", file)
			merged[file] = pEntries
			droppedFiles++
			continue
		}
		// Ranges match; merge hit counts per range.
		byRange := make(map[string]*entry, len(pEntries))
		for i := range pEntries {
			byRange[pEntries[i].rangeKey] = &pEntries[i]
		}
		for i := range sEntries {
			if e, ok := byRange[sEntries[i].rangeKey]; ok {
				if mode == "set" {
					if sEntries[i].hits > 0 || e.hits > 0 {
						e.hits = 1
					}
				} else {
					e.hits += sEntries[i].hits
				}
			}
		}
		mergedFiles++
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

	fmt.Fprintf(os.Stderr, "covmerge: %d files merged, %d files dropped (drift), %d files from secondary only\n",
		mergedFiles, droppedFiles, secondaryOnly)

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

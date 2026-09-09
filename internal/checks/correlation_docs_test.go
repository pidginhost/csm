package checks

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateCorrelationDocs rewrites the generated block in docs/src/incidents.md
// from the registry. Default runs are read-only.
var updateCorrelationDocs = flag.Bool("update-correlation-docs", false, "rewrite the generated correlation policy table in docs/src/incidents.md")

const (
	correlationTableBegin = "<!-- correlation-table:begin -->"
	correlationTableEnd   = "<!-- correlation-table:end -->"
	correlationDocsRel    = "docs/src/incidents.md"
)

// correlationClassLabel is the table label for a class.
func correlationClassLabel(c CorrelationClass) string {
	switch c {
	case CorrelationIgnored:
		return "ignored"
	case CorrelationSecurityEvent:
		return "security event"
	case CorrelationMalwareArtifact:
		return "malware artifact"
	case CorrelationDerived:
		return "derived"
	}
	return "unclassified"
}

// markdownCell makes a value safe inside a table cell: delimiters and
// backslashes are escaped and line breaks become spaces, so a value can
// never open or close a row.
func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// renderCorrelationTable renders the policy block: a legend of reason and
// gap tokens with their sentences, then one row per check sorted by name.
// The input is copied, never reordered in place. Output is ASCII with LF.
func renderCorrelationTable(rows []CheckInfo) string {
	sorted := append([]CheckInfo(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteString("Ignore reasons:\n\n")
	for _, token := range sortedKeys(correlationReasonSentences) {
		fmt.Fprintf(&b, "- `%s`: %s\n", markdownCell(token), markdownCell(correlationReasonSentences[token]))
	}
	b.WriteString("\nAttribution gaps:\n\n")
	for _, token := range sortedKeys(correlationGapSentences) {
		fmt.Fprintf(&b, "- `%s`: %s\n", markdownCell(token), markdownCell(correlationGapSentences[token]))
	}
	b.WriteString("\n| Check | Class | Ignore reason | Attribution gap |\n| --- | --- | --- | --- |\n")
	for _, c := range sorted {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n",
			markdownCell(c.Name), correlationClassLabel(c.Correlation),
			markdownCell(c.CorrelationReason), markdownCell(c.CorrelationGap))
	}
	return b.String()
}

var errCorrelationMarkers = errors.New("correlation-table markers: expected exactly one begin marker followed by exactly one end marker")

// markedBlock locates the single ordered marker pair and returns the byte
// offsets of the interior (after the begin line, before the end marker).
func markedBlock(doc []byte) (start, end int, err error) {
	begin := []byte(correlationTableBegin)
	stop := []byte(correlationTableEnd)
	if bytes.Count(doc, begin) != 1 || bytes.Count(doc, stop) != 1 {
		return 0, 0, errCorrelationMarkers
	}
	bi := bytes.Index(doc, begin)
	ei := bytes.Index(doc, stop)
	if ei < bi+len(begin) {
		return 0, 0, errCorrelationMarkers
	}
	start = bi + len(begin)
	if bytes.HasPrefix(doc[start:], []byte("\r\n")) {
		start += 2
	} else if start < len(doc) && doc[start] == '\n' {
		start++
	}
	return start, ei, nil
}

// replaceMarkedBlock returns doc with the marker interior replaced by body.
// Every byte outside the interior is preserved. Invalid marker structure
// returns an error and no document.
func replaceMarkedBlock(doc []byte, body string) ([]byte, error) {
	start, end, err := markedBlock(doc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(doc)+len(body))
	out = append(out, doc[:start]...)
	out = append(out, body...)
	out = append(out, doc[end:]...)
	return out, nil
}

// markedInterior returns the current interior of the marker pair.
func markedInterior(doc []byte) (string, error) {
	start, end, err := markedBlock(doc)
	if err != nil {
		return "", err
	}
	return string(doc[start:end]), nil
}

// checkCorrelationDocument compares the document at path against want. In
// update mode a mismatch rewrites only the marker interior; in read-only
// mode it returns the mismatch without touching the file. Malformed markers
// are an error in both modes and never write.
func checkCorrelationDocument(path, want string, update bool) (mismatch bool, err error) {
	doc, err := os.ReadFile(path) // #nosec G304 -- repository documentation path
	if err != nil {
		return false, err
	}
	got, err := markedInterior(doc)
	if err != nil {
		return false, err
	}
	if got == want {
		return false, nil
	}
	if !update {
		return true, nil
	}
	out, err := replaceMarkedBlock(doc, want)
	if err != nil {
		return true, err
	}
	return true, os.WriteFile(path, out, 0o644) // #nosec G306 -- repository documentation file
}

// The generated block in the incidents document must match the registry
// byte for byte. A stale, missing or duplicated row fails; the fix is the
// update flag, never a hand edit.
func TestCorrelationDocumentation(t *testing.T) {
	path := filepath.Join(repoRootFromSource(t), correlationDocsRel)
	want := renderCorrelationTable(checkRegistry)
	mismatch, err := checkCorrelationDocument(path, want, *updateCorrelationDocs)
	if err != nil {
		t.Fatalf("%s: %v", correlationDocsRel, err)
	}
	if mismatch && !*updateCorrelationDocs {
		t.Fatalf("%s: generated correlation table is stale.\nRun:\n  go test ./internal/checks -run '^TestCorrelationDocumentation$' -args -update-correlation-docs\nExpected block:\n%s", correlationDocsRel, want)
	}
}

func TestRenderCorrelationTableExactOutput(t *testing.T) {
	rows := []CheckInfo{
		{Name: "zeta", Category: CategoryWeb, Correlation: CorrelationSecurityEvent, CorrelationGap: gapSocketOwner},
		{Name: "alpha", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture},
		{Name: "mid", Category: CategoryWeb, Correlation: CorrelationDerived},
		{Name: "malw", Category: CategoryWeb, Correlation: CorrelationMalwareArtifact},
	}
	before := append([]CheckInfo(nil), rows...)
	got := renderCorrelationTable(rows)
	want := "Ignore reasons:\n\n" +
		"- `account-aggregate`: already summarizes several accounts without a single victim identity\n" +
		"- `attacker-side`: attacker activity or attempted access, not evidence of compromise of the named victim\n" +
		"- `host-scope`: host-wide condition with no account to attribute; a cross-account count cannot use it even when it is a real compromise\n" +
		"- `informational`: audit trail or inventory event with no compromise claim\n" +
		"- `performance`: resource usage\n" +
		"- `posture`: static configuration, hardening or hygiene state; a Critical means a misconfiguration, not an attack on the account\n" +
		"- `response`: record of an automatic action already taken; feeding it back would double count\n" +
		"- `self-health`: CSM's own health, capacity or coverage state\n" +
		"\nAttribution gaps:\n\n" +
		"- `envelope-sender`: volume aggregate keyed by the attacker-controlled envelope sender; no verified owner exists\n" +
		"- `partial-socket-owner`: periodic evaluator supplies no tenant; realtime process enrichment can supply one but can miss\n" +
		"- `socket-owner`: periodic socket finding has no hosting owner; an unattributed Critical is counted in diagnostics only\n" +
		"\n| Check | Class | Ignore reason | Attribution gap |\n| --- | --- | --- | --- |\n" +
		"| `alpha` | ignored | posture |  |\n" +
		"| `malw` | malware artifact |  |  |\n" +
		"| `mid` | derived |  |  |\n" +
		"| `zeta` | security event |  | socket-owner |\n"
	if got != want {
		t.Fatalf("rendered table:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "\r") || !strings.HasSuffix(got, "\n") {
		t.Fatal("output must use LF line endings and end with a newline")
	}
	for i := range rows {
		if rows[i] != before[i] {
			t.Fatal("renderer reordered its input")
		}
	}
	for _, r := range got {
		if r > 127 {
			t.Fatalf("non-ASCII byte in rendered table: %q", r)
		}
	}
}

func TestRenderCorrelationTableEscapesCells(t *testing.T) {
	rows := []CheckInfo{{Name: "a|b\\c\nd", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: "x|y\r\nz"}}
	got := renderCorrelationTable(rows)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	last := lines[len(lines)-1]
	if last != "| `a\\|b\\\\c d` | ignored | x\\|y z |  |" {
		t.Fatalf("escaped row = %q", last)
	}
	if strings.Count(got, "\n| `") != 1 {
		t.Fatalf("delimiter or newline in a cell opened extra rows:\n%s", got)
	}
}

func TestReplaceMarkedBlockValidatesMarkers(t *testing.T) {
	good := "intro\n" + correlationTableBegin + "\nold\n" + correlationTableEnd + "\noutro\n"
	cases := map[string]string{
		"missing both":     "intro\nold\noutro\n",
		"missing begin":    "intro\nold\n" + correlationTableEnd + "\n",
		"missing end":      "intro\n" + correlationTableBegin + "\nold\n",
		"reversed":         correlationTableEnd + "\nold\n" + correlationTableBegin + "\n",
		"duplicated":       good + correlationTableBegin + "\nmore\n" + correlationTableEnd + "\n",
		"duplicated begin": correlationTableBegin + "\n" + good,
		"duplicated end":   good + correlationTableEnd + "\n",
		"nested":           correlationTableBegin + "\n" + correlationTableBegin + "\nx\n" + correlationTableEnd + "\n",
		"nested pairs":     correlationTableBegin + "\n" + good + correlationTableEnd + "\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if out, err := replaceMarkedBlock([]byte(doc), "new\n"); !errors.Is(err, errCorrelationMarkers) || out != nil {
				t.Fatalf("replacement = %q, err = %v, want nil and marker error", out, err)
			}
			path := filepath.Join(t.TempDir(), "incidents.md")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, update := range []bool{false, true} {
				if _, err := checkCorrelationDocument(path, "new\n", update); !errors.Is(err, errCorrelationMarkers) {
					t.Fatalf("update=%v: err = %v, want marker error", update, err)
				}
				got, err := os.ReadFile(path) // #nosec G304 -- temp fixture
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, []byte(doc)) {
					t.Fatalf("update=%v changed a malformed document", update)
				}
			}
		})
	}
	out, err := replaceMarkedBlock([]byte(good), "new\n")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "intro\n"+correlationTableBegin+"\nnew\n"+correlationTableEnd+"\noutro\n" {
		t.Fatalf("replacement = %q", out)
	}
}

func TestCorrelationDocumentPreservesMarkerLines(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(fmt.Sprintf("newline_%q", newline), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "incidents.md")
			prefix := "intro" + newline + correlationTableBegin + newline
			suffix := correlationTableEnd + newline + "outro" + newline
			doc := prefix + "old" + newline + suffix
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			body := renderCorrelationTable(checkRegistry)
			mismatch, err := checkCorrelationDocument(path, body, true)
			if err != nil || !mismatch {
				t.Fatalf("update mismatch = %v, err = %v", mismatch, err)
			}
			got, err := os.ReadFile(path) // #nosec G304 -- temp fixture
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(prefix+body+suffix)) {
				t.Fatal("update changed bytes outside the generated block")
			}
			if mismatch, err := checkCorrelationDocument(path, body, false); err != nil || mismatch {
				t.Fatalf("updated document mismatch = %v, err = %v", mismatch, err)
			}
		})
	}
}

// Round trip: a rendered block written through the updater reads back
// identically, and every byte outside the markers survives.
func TestCorrelationDocumentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incidents.md")
	prose := "# Heading\n\nprose before\n\n" + correlationTableBegin + "\nstale\n" + correlationTableEnd + "\n\nprose after\n"
	if err := os.WriteFile(path, []byte(prose), 0o600); err != nil {
		t.Fatal(err)
	}
	want := renderCorrelationTable(checkRegistry)

	// Read-only mode reports the mismatch and never writes.
	mismatch, err := checkCorrelationDocument(path, want, false)
	if err != nil || !mismatch {
		t.Fatalf("read-only mismatch = %v, err = %v", mismatch, err)
	}
	if got, _ := os.ReadFile(path); string(got) != prose { // #nosec G304 -- temp fixture
		t.Fatal("read-only mode wrote the document")
	}

	// Update mode rewrites the interior only.
	if _, err := checkCorrelationDocument(path, want, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- temp fixture
	if !strings.HasPrefix(string(got), "# Heading\n\nprose before\n\n"+correlationTableBegin+"\n") || !strings.HasSuffix(string(got), correlationTableEnd+"\n\nprose after\n") {
		t.Fatalf("prose outside the markers changed:\n%s", got)
	}
	if mismatch, err := checkCorrelationDocument(path, want, false); err != nil || mismatch {
		t.Fatalf("round trip mismatch = %v, err = %v", mismatch, err)
	}

	// Stale, missing and duplicated rows are all mismatches.
	stale := append([]CheckInfo(nil), checkRegistry...)
	stale[0].Correlation = CorrelationDerived
	missing := checkRegistry[1:]
	duplicate := append(append([]CheckInfo(nil), checkRegistry...), checkRegistry[0])
	for name, rows := range map[string][]CheckInfo{"stale": stale, "missing": missing, "duplicate": duplicate} {
		if mismatch, err := checkCorrelationDocument(path, renderCorrelationTable(rows), false); err != nil || !mismatch {
			t.Errorf("%s rows not detected: mismatch=%v err=%v", name, mismatch, err)
		}
	}

	// A malformed document is left byte-identical even in update mode.
	broken := filepath.Join(dir, "broken.md")
	body := "x\n" + correlationTableBegin + "\n" + correlationTableBegin + "\ny\n" + correlationTableEnd + "\n"
	if err := os.WriteFile(broken, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkCorrelationDocument(broken, want, true); !errors.Is(err, errCorrelationMarkers) {
		t.Fatalf("malformed markers err = %v", err)
	}
	if got, _ := os.ReadFile(broken); string(got) != body { // #nosec G304 -- temp fixture
		t.Fatal("malformed document was modified")
	}
}

// The document is found from the source tree, not the working directory.
func TestCorrelationDocumentationIgnoresWorkingDirectory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	path := filepath.Join(repoRootFromSource(t), correlationDocsRel)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("documentation path not resolved from source: %v", err)
	}
}

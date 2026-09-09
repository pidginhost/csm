// Command finding-stream turns CSM audit logs into an anonymized finding
// stream for correlation and threshold calibration.
//
//	finding-stream anonymize --salt-file .cache/finding-streams/salt \
//	    --out .cache/finding-streams/host.jsonl.gz audit.jsonl audit.jsonl-*.gz
//
// Inputs are audit.jsonl files (plain or gzip). The output is gzip JSONL in
// the same schema with every host, account, domain, mailbox and address
// replaced by a salted pseudonym, and a leak check that refuses to write
// output still carrying a raw identifier. The salt file is created on first
// use (mode 0600) and must be kept private and reused across hosts so their
// streams share pseudonyms. Collection is a read-only copy of the log
// files; nothing here runs on the monitored host.
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "finding-stream:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "anonymize" {
		return errors.New("usage: finding-stream anonymize --salt-file FILE --out FILE.jsonl.gz INPUT [INPUT]")
	}
	fs := flag.NewFlagSet("anonymize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	saltPath := fs.String("salt-file", ".cache/finding-streams/salt", "private salt; created when absent")
	outPath := fs.String("out", "", "output file (gzip JSONL)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	inputs := fs.Args()
	if *outPath == "" || len(inputs) == 0 {
		return errors.New("anonymize needs --out and at least one input file")
	}
	salt, err := loadOrCreateSalt(*saltPath)
	if err != nil {
		return err
	}

	var events []alert.AuditEvent
	for _, in := range inputs {
		batch, err := readEvents(in)
		if err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
		events = append(events, batch...)
	}
	a := NewAnonymizer(salt)
	a.Learn(events)
	out := make([]alert.AuditEvent, 0, len(events))
	for _, e := range events {
		out = append(out, a.Event(e))
	}
	if problems := a.Verify(out); len(problems) > 0 {
		limit := problems
		if len(limit) > 10 {
			limit = limit[:10]
		}
		return fmt.Errorf("leak check failed on %d event(s); nothing written:\n%s", len(problems), strings.Join(limit, "\n"))
	}
	if err := writeEvents(*outPath, out); err != nil {
		return err
	}
	writeSummary(stdout, *outPath, out, a, salt)
	return nil
}

func loadOrCreateSalt(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-chosen salt path
		if len(b) < 32 {
			return nil, fmt.Errorf("salt file %s is shorter than 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return nil, err
	}
	return salt, nil
}

func readEvents(path string) ([]alert.AuditEvent, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-chosen input file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	var events []alert.AuditEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var e alert.AuditEvent
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func writeEvents(path string, events []alert.AuditEvent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen output file
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	w := bufio.NewWriter(zw)
	enc := json.NewEncoder(w)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writeSummary(w io.Writer, outPath string, events []alert.AuditEvent, a *Anonymizer, salt []byte) {
	byCheck := map[string]int{}
	for i := range events {
		byCheck[events[i].Check]++
	}
	names := make([]string, 0, len(byCheck))
	for n := range byCheck {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if byCheck[names[i]] != byCheck[names[j]] {
			return byCheck[names[i]] > byCheck[names[j]]
		}
		return names[i] < names[j]
	})
	fmt.Fprintf(w, "output: %s\n", outPath)
	fmt.Fprintf(w, "events: %d\n", len(events))
	if len(events) > 0 {
		first, last := events[0].Timestamp, events[0].Timestamp
		for i := range events {
			if events[i].Timestamp.Before(first) {
				first = events[i].Timestamp
			}
			if events[i].Timestamp.After(last) {
				last = events[i].Timestamp
			}
		}
		fmt.Fprintf(w, "span: %s .. %s\n", first.UTC().Format("2006-01-02T15:04:05Z"), last.UTC().Format("2006-01-02T15:04:05Z"))
	}
	counts := a.Counts()
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(w, "replaced %s: %d\n", k, counts[k])
	}
	fmt.Fprintf(w, "leak check: clean\n")
	sum := sha256.Sum256(salt)
	fmt.Fprintf(w, "salt fingerprint: %s\n", hex.EncodeToString(sum[:6]))
	fmt.Fprintln(w, "checks:")
	for _, n := range names {
		fmt.Fprintf(w, "  %s: %d\n", n, byCheck[n])
	}
}

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

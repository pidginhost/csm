package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func tailRecordsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})
	return path
}

func recordTexts(records []syslogRecord) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.text
	}
	return out
}

// A re-read window keeps each line's start offset and the file it came from,
// with the line semantics tailFile has always had: blank lines and a final
// unterminated line included, CRLF endings trimmed. The unterminated line
// names no file: its writer can still append to it.
func TestTailFileRecordsKeepOffsetsAndTheFile(t *testing.T) {
	path := tailRecordsFile(t, "a\n\nb\r\nc")
	stream := syslogTestRef(t, path, 0, "").Stream
	got := tailFileRecords("/anything", 10)
	want := []syslogRecord{{text: "a", offset: 0, stream: stream}, {text: "", offset: 2, stream: stream},
		{text: "b", offset: 3, stream: stream}, {text: "c", offset: 6, unterminated: true}}
	if !slices.Equal(got, want) {
		t.Fatalf("records %+v, want %+v", got, want)
	}
	if last := tailFileRecords("/anything", 2); !slices.Equal(last, want[2:]) {
		t.Fatalf("last two records %+v, want %+v", last, want[2:])
	}
}

// A large file is read through its tail window; offsets stay those of the
// file, not of the window.
func TestTailFileRecordsLargeFileWindowOffsets(t *testing.T) {
	var b strings.Builder
	var want []syslogRecord
	for i := 1; i <= 7000; i++ {
		line := fmt.Sprintf("LINE-%04d %s", i, strings.Repeat("X", 180))
		want = append(want, syslogRecord{text: line, offset: int64(b.Len())})
		b.WriteString(line + "\n")
	}
	path := tailRecordsFile(t, b.String())
	stream := syslogTestRef(t, path, 0, "").Stream
	for i := range want {
		want[i].stream = stream
	}
	if got := tailFileRecords("/anything", 3000); !slices.Equal(got, want[4000:]) {
		t.Fatalf("got %d records from %+v, want lines 4001 to 7000 at their file offsets", len(got), got[0])
	}
}

// An oversized record is skipped and the next record keeps its true offset.
func TestTailFileRecordsSkipOversizedRecordKeepingOffsets(t *testing.T) {
	oversized := strings.Repeat("A", maxLogLineBytes+32)
	tailRecordsFile(t, "safe-before\n"+oversized+"\nsafe-after\n")
	got := tailFileRecords("/anything", 10)
	if len(got) != 2 || got[0].text != "safe-before" || got[0].offset != 0 ||
		got[1].text != "safe-after" || got[1].offset != int64(len("safe-before\n")+len(oversized)+1) {
		t.Fatalf("records %+v, want safe-before at 0 and safe-after after the oversized record", got)
	}
}

// tailFile is the text of tailFileRecords, for every shape of input.
func TestTailFileIsTheTextOfItsRecords(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"blank":     "\n\n",
		"crlf":      "one\r\ntwo\r\n",
		"partial":   "one\ntwo",
		"oversized": "a\n" + strings.Repeat("B", maxLogLineBytes+1) + "\nc\n",
		"large":     strings.Repeat(strings.Repeat("x", 1023)+"\n", 2048),
	} {
		t.Run(name, func(t *testing.T) {
			tailRecordsFile(t, content)
			for _, n := range []int{1, 3, 5000} {
				if lines, records := tailFile("/anything", n), tailFileRecords("/anything", n); !slices.Equal(lines, recordTexts(records)) {
					t.Fatalf("tail %d: lines %q, records %+v", n, lines, records)
				}
			}
		})
	}
}

// A window read that comes back short cannot be placed in the file; the tail
// falls back to reading the whole file rather than guess offsets.
func TestReadTailWindowRefusesAShortRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x\n", 2048)), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if data, start, err := readTailWindow(f, 8192, 10, 1<<20); err == nil {
		t.Fatalf("short read gave %d bytes at %d", len(data), start)
	}
}

// A record still being written has no reference: the writer may append more
// fields to it. The text projection keeps it as tailFile always has. Once its
// line ends it is named by its unchanged offset and its complete bytes, as
// the follow reader names it from either follow state.
func TestTailFileRecordsDoNotNameAnUnfinishedWrite(t *testing.T) {
	prefix := `203.0.113.5 - - [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0`
	var large strings.Builder
	for i := 1; i <= 7000; i++ {
		fmt.Fprintf(&large, "LINE-%04d %s\n", i, strings.Repeat("X", 180))
	}
	for name, c := range map[string]struct{ before, rest string }{
		"small":     {"first\n", ` "-" "Mozilla/5.0" "-" "-" 2083` + "\n"},
		"crlf":      {"first\r\n", ` "-" "Mozilla/5.0" "-" "-" 2083` + "\r\n"},
		"large":     {large.String(), ` "-" "Mozilla/5.0" "-" "-" 2083` + "\n"},
		"oversized": {"first\n" + strings.Repeat("A", maxLogLineBytes+32) + "\n", ` "-" "-" "-" "-" 2083` + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			path := tailRecordsFile(t, c.before+prefix)
			offset := int64(len(c.before))
			lines := tailFile("/anything", 10)
			records := tailFileRecords("/anything", 10)
			if len(lines) == 0 || lines[len(lines)-1] != prefix || len(records) == 0 {
				t.Fatalf("tail lines %q, records %+v: want the unfinished text last", lines, records)
			}
			if last := records[len(records)-1]; last.text != prefix || last.offset != offset || last.stream != "" {
				t.Fatalf("unfinished record %+v, want %q at %d with no stream", last, prefix, offset)
			}
			_, partialState, _, err := readNewSyslogRecords(path, followState{})
			if err != nil {
				t.Fatal(err)
			}

			w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.WriteString(c.rest); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			full := prefix + strings.TrimRight(c.rest, "\r\n")
			records = tailFileRecords("/anything", 10)
			last := records[len(records)-1]
			want := syslogTestRef(t, path, offset, full)
			if last.text != full || last.offset != offset || last.stream != want.Stream || alert.RecordCursor(last.offset, last.text) != want.Cursor {
				t.Fatalf("finished record %+v, want %q at %d named %+v", last, full, offset, want)
			}
			for stateName, st := range map[string]followState{"partial read": partialState, "fresh": {}} {
				followed, _, _, err := readNewSyslogRecords(path, st)
				if err != nil {
					t.Fatal(err)
				}
				var found bool
				for _, r := range followed {
					if r.offset != offset {
						continue
					}
					found = true
					if o := r.observation(ProducerFTPScan, time.Unix(1, 0)); o.Stream != want.Stream || o.Cursor != want.Cursor {
						t.Fatalf("%s follow read named %+v, tail named %+v", stateName, o, want)
					}
				}
				if !found {
					t.Fatalf("%s follow read has no record at %d: %+v", stateName, offset, followed)
				}
			}
		})
	}
}

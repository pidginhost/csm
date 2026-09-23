package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type countingReaderAt struct {
	data []byte
	read int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r := bytes.NewReader(c.data)
	n, err := r.ReadAt(p, off)
	c.read += n
	return n, err
}

func auditLines(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		line, err := json.Marshal(UIAuditEntry{Action: "block_ip", Target: fmt.Sprintf("198.51.100.%d", i%250), Details: fmt.Sprintf("entry %d", i)})
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// The audit page asks for the newest 200 entries of a log that can reach
// 10 MB. Reading it from the end stops once the entries are found.
func TestAuditTailReadsOnlyTheEnd(t *testing.T) {
	data := auditLines(t, 50000)
	r := &countingReaderAt{data: data}
	got := tailAuditEntries(r, int64(len(data)), 10)
	if len(got) != 10 || got[0].Details != "entry 49999" || got[9].Details != "entry 49990" {
		t.Fatalf("got %d entries, first %+v", len(got), got)
	}
	if r.read > len(data)/10 {
		t.Fatalf("read %d of %d bytes for 10 entries", r.read, len(data))
	}
}

func TestAuditTailMatchesAFullRead(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(auditLines(t, 3))
	buf.WriteString("not json\n\n")
	long, _ := json.Marshal(UIAuditEntry{Action: "undo_bulk", Details: strings.Repeat("x", 300*1024)})
	buf.Write(long)
	buf.WriteByte('\n')
	last, _ := json.Marshal(UIAuditEntry{Action: "last"})
	buf.Write(last) // no trailing newline
	data := buf.Bytes()

	got := tailAuditEntries(&countingReaderAt{data: data}, int64(len(data)), 0)
	if len(got) != 5 {
		t.Fatalf("got %d entries, want 5 (bad and blank lines skipped)", len(got))
	}
	if got[0].Action != "last" || got[1].Action != "undo_bulk" || len(got[1].Details) != 300*1024 || got[4].Details != "entry 0" {
		t.Fatalf("order or content wrong: %s, %s, %s", got[0].Action, got[1].Action, got[4].Details)
	}
	if two := tailAuditEntries(&countingReaderAt{data: data}, int64(len(data)), 2); len(two) != 2 || two[1].Action != "undo_bulk" {
		t.Fatalf("limit 2 = %+v", two)
	}
}

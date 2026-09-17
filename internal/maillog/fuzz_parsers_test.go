package maillog

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"
)

func FuzzPendingLogLine(f *testing.F) {
	f.Add([]byte("user=<alice@example.test> auth failed\nnext\npartial"), uint8(7))
	f.Add([]byte(strings.Repeat("a", 128)+"\nvalid\n"), uint8(3))
	f.Add([]byte("\n\x00\r\n"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, fragment uint8) {
		const limit = 64
		var input bytes.Buffer
		reader := bufio.NewReaderSize(&input, 16)
		var pending pendingLogLine
		var got, want []string
		for _, line := range bytes.SplitAfter(data, []byte{'\n'}) {
			if len(line) <= limit && bytes.HasSuffix(line, []byte{'\n'}) {
				want = append(want, string(line))
			}
		}
		for offset := 0; offset < len(data); {
			end := min(len(data), offset+int(fragment)+1)
			input.Write(data[offset:end])
			offset = end
			for {
				line, truncated, err := pending.read(context.Background(), reader, limit)
				if pending.data.Len() > limit {
					t.Fatal("pending line exceeded its memory bound")
				}
				if err == io.EOF {
					if line != "" || truncated {
						t.Fatalf("EOF exposed an incomplete record: %q, truncated=%v", line, truncated)
					}
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if !truncated {
					got = append(got, line)
				}
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("records = %q, want %q", got, want)
		}
	})
}

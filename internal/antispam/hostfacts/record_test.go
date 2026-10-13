package hostfacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestCollectRecordStates(t *testing.T) {
	d := t.TempDir()
	incomplete := string(antispam.EncodeRecord(""))
	complete := string(antispam.EncodeRecord(strings.Repeat("a", 64)))
	limit := incomplete + strings.Repeat(" ", antispam.MaxRecordBytes-len(incomplete))
	for name, content := range map[string]string{
		"incomplete": incomplete, "complete": complete, "invalid": "{", "empty": "",
		"limit": limit, "oversized": limit + " ",
	} {
		write(t, filepath.Join(d, name), content)
	}
	mkdir(t, filepath.Join(d, "directory"))
	for name, target := range map[string]string{
		"symlink": "complete", "dangling": "absent", "parent": "directory", "dangling-parent": "absent",
	} {
		if err := os.Symlink(target, filepath.Join(d, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, content string
		missing, bad  bool
	}{
		{name: "absent", missing: true},
		{name: "absent/installed.json", missing: true},
		{name: "incomplete", content: incomplete},
		{name: "complete", content: complete},
		{name: "invalid", content: "{"},
		{name: "empty"},
		{name: "limit", content: limit},
		{name: "oversized", bad: true},
		{name: "directory", bad: true},
		{name: "complete/installed.json", bad: true},
		{name: "symlink", bad: true},
		{name: "dangling", bad: true},
		{name: "parent/installed.json", bad: true},
		{name: "dangling-parent/installed.json", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testCollector(d, &fakeRun{})
			c.layout.Record = filepath.Join(d, tc.name)
			for name, collect := range map[string]func() antispam.HostFacts{
				"full":      func() antispam.HostFacts { return c.collect(context.Background(), "/csm-antispam-test-missing/s") },
				"installed": c.installed,
			} {
				t.Run(name, func(t *testing.T) {
					got := collect().Record
					if got.Missing != tc.missing || (got.Err != nil) != tc.bad || got.Content != tc.content {
						t.Fatalf("record: missing %t, error %v, %d bytes; want missing %t, error %t, %d bytes",
							got.Missing, got.Err, len(got.Content), tc.missing, tc.bad, len(tc.content))
					}
				})
			}
		})
	}
}

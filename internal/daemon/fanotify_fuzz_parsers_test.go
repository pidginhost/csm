//go:build linux

package daemon

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/checks"
)

func FuzzPHPNamespaceScopes(f *testing.F) {
	for _, source := range []string{
		"<?php system($_POST['x']);",
		"<?php namespace App; system($_POST['x']);",
		"<?php namespace Decoy {} namespace { system($_POST['x']); }",
		"<?php namespace App { use function Vendor\\run as system; system($_POST['x']); }",
		"<?php $b = file_get_contents('php://input'); system($b);",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1<<16 {
			return
		}
		structure := strings.ToLower(checks.PHPRequestFlowStructure(source))
		masked := maskUserDispatchedPHPCalls(structure)
		if len(masked) != len(structure) {
			t.Fatalf("masked length=%d, want %d", len(masked), len(structure))
		}
		for _, scope := range phpNamespaceScopes(structure) {
			if scope.id < 1 || scope.start < 0 || scope.start > scope.end || scope.end > len(structure) {
				t.Fatalf("invalid namespace scope: %+v for length %d", scope, len(structure))
			}
		}
	})
}

func FuzzParseFIDRecord(f *testing.F) {
	f.Add(capturedCreate)
	f.Add(fidEventRecord(unix.FAN_Q_OVERFLOW))
	f.Add(fidEventRecord(unix.FAN_MOVED_TO, fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_PIDFD, []byte{5, 0, 0, 0}),
		fidInfoRecord(unix.FAN_EVENT_INFO_TYPE_DFID_NAME, dfidNameBody(8, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "x.php"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, size, err := parseFIDRecord(b)
		if size < 0 || size > len(b) || (size > 0 && size < metadataSize) {
			t.Fatalf("size %d for a %d-byte buffer", size, len(b))
		}
		if err != nil || rec.Mask&unix.FAN_Q_OVERFLOW != 0 {
			return
		}
		if size == 0 || len(rec.Handle) == 0 || len(rec.Handle) > maxFileHandleSize {
			t.Fatalf("accepted record with size %d, handle %d bytes", size, len(rec.Handle))
		}
		if rec.Name == "" || rec.Name == "." || rec.Name == ".." || strings.ContainsAny(rec.Name, "/\x00") {
			t.Fatalf("accepted entry name %q", rec.Name)
		}
	})
}

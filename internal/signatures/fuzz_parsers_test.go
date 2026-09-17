package signatures

import (
	"bytes"
	"testing"
)

func FuzzReferencedPayloadPaths(f *testing.F) {
	f.Add([]byte("<?php include'payload.jpe';"))
	f.Add([]byte("<?php $p = '/assets/logo.png'; include($p);"))
	f.Add([]byte("<?php include 'same.png'; include 'same.png';"))
	f.Add([]byte("<?php include 'code.php';"))
	f.Fuzz(func(t *testing.T, content []byte) {
		paths := ReferencedPayloadPaths(content)
		if len(paths) > maxReferencedPayloadPaths {
			t.Fatalf("unbounded path count: %d", len(paths))
		}
		seen := make(map[string]bool)
		for _, path := range paths {
			if seen[path] || path == "" || !bytes.Contains(content, []byte(path)) {
				t.Fatalf("duplicate or fabricated path: %q", path)
			}
			seen[path] = true
		}
	})
}

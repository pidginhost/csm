package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Two conf.d fragments that set the same scalar key silently let
// last-merged win. Without a collision signal the operator never finds
// out which fragment's value is live until production behaviour
// surprises them.
func TestDeepMergeTracked_ReportsScalarCollision(t *testing.T) {
	base := mustYAML(t, "hostname: a.example\nmail_logs:\n  source: file\n")
	overlay := mustYAML(t, "hostname: b.example\nmail_logs:\n  source: journal\n")

	var got []collisionEvent
	DeepMergeTracked(base, overlay, func(key, oldVal, newVal string) {
		got = append(got, collisionEvent{key, oldVal, newVal})
	})

	if len(got) != 2 {
		t.Fatalf("got %d collisions, want 2: %+v", len(got), got)
	}
	wantByKey := map[string]collisionEvent{
		"hostname":         {"hostname", "a.example", "b.example"},
		"mail_logs.source": {"mail_logs.source", "file", "journal"},
	}
	for _, ev := range got {
		want, ok := wantByKey[ev.key]
		if !ok {
			t.Errorf("unexpected collision: %+v", ev)
			continue
		}
		if ev != want {
			t.Errorf("collision %s: got %+v, want %+v", ev.key, ev, want)
		}
	}
}

// Sequence + sequence merges do not replace the existing value. Two fragments
// contributing entries to the same list is not a collision the operator needs
// to know about, even when scalar duplicates are collapsed.
func TestDeepMergeTracked_NoCollisionOnSequenceAppend(t *testing.T) {
	base := mustYAML(t, "infra_ips:\n  - 10.0.0.1\n")
	overlay := mustYAML(t, "infra_ips:\n  - 10.0.0.2\n")

	var got []collisionEvent
	DeepMergeTracked(base, overlay, func(key, oldVal, newVal string) {
		got = append(got, collisionEvent{key, oldVal, newVal})
	})

	if len(got) != 0 {
		t.Errorf("expected no collisions for sequence append, got %+v", got)
	}
}

// A scalar that overlay leaves at the same value is still a write,
// but the operator does not need to see it. Skipping no-op overrides
// keeps the warning surface useful.
func TestDeepMergeTracked_SkipsIdenticalScalar(t *testing.T) {
	base := mustYAML(t, "hostname: a.example\n")
	overlay := mustYAML(t, "hostname: a.example\n")

	var got []collisionEvent
	DeepMergeTracked(base, overlay, func(key, oldVal, newVal string) {
		got = append(got, collisionEvent{key, oldVal, newVal})
	})

	if len(got) != 0 {
		t.Errorf("expected no collisions for identical scalar, got %+v", got)
	}
}

// DeepMerge keeps its existing no-arg signature for callers that do
// not care about collisions. The trackless path must not regress.
func TestDeepMerge_SignaturePreserved(t *testing.T) {
	base := mustYAML(t, "hostname: a\n")
	overlay := mustYAML(t, "hostname: b\n")

	out := DeepMerge(base, overlay)
	if out == nil {
		t.Fatal("DeepMerge returned nil")
	}
}

func TestLoadWithDir_RedactsSecretCollisionValues(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("webui:\n  auth_token: old-secret\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-webui.yaml"), []byte("webui:\n  auth_token: new-secret\n"), 0o600))

	stderr := captureStderr(t, func() {
		cfg, err := LoadWithDir(main, confd)
		if err != nil {
			t.Fatalf("LoadWithDir: %v", err)
		}
		if cfg.WebUI.AuthToken != "new-secret" {
			t.Fatalf("WebUI.AuthToken = %q, want new-secret", cfg.WebUI.AuthToken)
		}
	})

	if strings.Contains(stderr, "old-secret") || strings.Contains(stderr, "new-secret") {
		t.Fatalf("collision log leaked secret values: %q", stderr)
	}
	if !strings.Contains(stderr, "webui.auth_token") {
		t.Fatalf("collision log missing key path: %q", stderr)
	}
	if !strings.Contains(stderr, "10-webui.yaml") {
		t.Fatalf("collision log missing fragment path: %q", stderr)
	}
	if strings.Count(stderr, redactedValue) != 2 {
		t.Fatalf("collision log = %q, want both values redacted", stderr)
	}
}

type collisionEvent struct {
	key    string
	oldVal string
	newVal string
}

func mustYAML(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatal(err)
	}
	return &n
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = old
	}()

	fn()

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close stderr writer: %v", closeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("close stderr reader: %v", closeErr)
	}
	return string(out)
}

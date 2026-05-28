package config

import (
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

// Sequence + sequence appends. Two fragments contributing extra
// entries to the same list is the documented merge semantics, not a
// collision the operator needs to know about.
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

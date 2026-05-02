package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDeepMerge_ScalarLaterWins(t *testing.T) {
	base := unmarshalDoc(t, `hostname: original`)
	overlay := unmarshalDoc(t, `hostname: replaced`)
	got := DeepMerge(base, overlay)
	root := got.Content[0]
	if root.Content[1].Value != "replaced" {
		t.Fatalf("expected scalar overwritten, got %q", root.Content[1].Value)
	}
}

func TestDeepMerge_SequenceAppends(t *testing.T) {
	base := unmarshalDoc(t, "infra_ips:\n  - 1.1.1.1\n")
	overlay := unmarshalDoc(t, "infra_ips:\n  - 2.2.2.2\n")
	got := DeepMerge(base, overlay)
	seq := fieldOf(t, got.Content[0], "infra_ips")
	if len(seq.Content) != 2 || seq.Content[0].Value != "1.1.1.1" || seq.Content[1].Value != "2.2.2.2" {
		t.Fatalf("expected [1.1.1.1, 2.2.2.2], got %v", flatten(seq))
	}
}

func TestDeepMerge_MapRecurses(t *testing.T) {
	base := unmarshalDoc(t, "webui:\n  enabled: true\n  port: 9443\n")
	overlay := unmarshalDoc(t, "webui:\n  port: 9000\n")
	got := DeepMerge(base, overlay)
	web := fieldOf(t, got.Content[0], "webui")
	if fieldOf(t, web, "port").Value != "9000" {
		t.Fatalf("expected port overridden, got %q", fieldOf(t, web, "port").Value)
	}
	if fieldOf(t, web, "enabled").Value != "true" {
		t.Fatalf("expected enabled retained, got %q", fieldOf(t, web, "enabled").Value)
	}
}

func TestDeepMerge_KindMismatchReplaces(t *testing.T) {
	base := unmarshalDoc(t, "infra_ips:\n  - a\n")
	overlay := unmarshalDoc(t, "infra_ips: replaced\n")
	got := DeepMerge(base, overlay)
	n := fieldOf(t, got.Content[0], "infra_ips")
	if n.Kind != yaml.ScalarNode || n.Value != "replaced" {
		t.Fatalf("expected scalar 'replaced' to replace sequence, got kind=%v value=%q", n.Kind, n.Value)
	}
}

func unmarshalDoc(t *testing.T, s string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatal(err)
	}
	return &n
}

func fieldOf(t *testing.T, m *yaml.Node, key string) *yaml.Node {
	t.Helper()
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	t.Fatalf("field %q not found", key)
	return nil
}

func flatten(seq *yaml.Node) []string {
	out := make([]string, 0, len(seq.Content))
	for _, n := range seq.Content {
		out = append(out, n.Value)
	}
	return out
}

func TestDeepMerge_EmptyBaseAdoptsOverlay(t *testing.T) {
	base := unmarshalDoc(t, ``)
	overlay := unmarshalDoc(t, "hostname: from-overlay\n")
	got := DeepMerge(base, overlay)
	root := got.Content[0]
	if fieldOf(t, root, "hostname").Value != "from-overlay" {
		t.Fatalf("expected empty base to adopt overlay content, got %q", fieldOf(t, root, "hostname").Value)
	}
}

func TestDeepMerge_EmptyOverlayLeavesBase(t *testing.T) {
	base := unmarshalDoc(t, "hostname: original\n")
	overlay := unmarshalDoc(t, ``)
	got := DeepMerge(base, overlay)
	root := got.Content[0]
	if fieldOf(t, root, "hostname").Value != "original" {
		t.Fatalf("expected empty overlay to leave base unchanged, got %q", fieldOf(t, root, "hostname").Value)
	}
}

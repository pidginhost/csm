package main

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
)

func manifestFixture(t *testing.T) (fs.FS, queueManifest) {
	t.Helper()
	root := queueFixture(map[string]string{
		"internal/example/queue.go": `package example
const limit = 4
type spool struct { pending map[string]int }
func start() { jobs := make(chan int, limit); _ = jobs }
`,
	})
	allocations, err := scanSources(root)
	if err != nil {
		t.Fatal(err)
	}
	publication := testEvidence{Package: modulePath + "/internal/example", Name: "TestPublished", Mode: "portable"}
	lifecycle := testEvidence{Package: modulePath + "/internal/example", Name: "TestLifecycle", Mode: "portable"}
	kernel := testEvidence{Package: modulePath + "/internal/example", Name: "TestKernel", Mode: "kernel"}
	return root, queueManifest{
		Version:     1,
		Allocations: []allocationDecision{{allocation: allocations[0], Class: "work", Queue: "example.jobs", Rationale: "Worker handoff."}},
		Owners: []queueOwner{
			{ID: "example.jobs", Rows: []string{"example.jobs"}, Bounds: "Four waiting jobs and one worker.", Publication: []testEvidence{publication}, Lifecycle: []testEvidence{lifecycle, kernel}},
			{ID: "example.spool", Rows: []string{"example.spool"}, Bounds: "Durable source has no fixed entry cap.", Anchors: []sourceAnchor{{Path: "internal/example/queue.go", Symbol: "spool.pending", Shape: "map[string]int"}}, Publication: []testEvidence{publication}, Lifecycle: []testEvidence{lifecycle}},
		},
	}
}

func TestManifestRequiresExactReviewedAllocationShapes(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*queueManifest)
	}{
		{"missing", "unclassified allocation", func(m *queueManifest) { m.Allocations = nil }},
		{"stale", "stale allocation", func(m *queueManifest) { m.Allocations[0].ID += "removed" }},
		{"changed capacity", "allocation changed", func(m *queueManifest) { m.Allocations[0].Capacity = "8" }},
		{"changed source", "allocation changed", func(m *queueManifest) { m.Allocations[0].Source = "make(chan string, limit)" }},
		{"changed default", "allocation changed", func(m *queueManifest) { m.Allocations[0].Defaults = []string{"limit = 8"} }},
		{"duplicate", "duplicate allocation", func(m *queueManifest) { m.Allocations = append(m.Allocations, m.Allocations[0]) }},
		{"unclassified", "unknown allocation class", func(m *queueManifest) { m.Allocations[0].Class = "" }},
		{"missing owner", "work allocation needs an owner", func(m *queueManifest) { m.Allocations[0].Queue = "" }},
		{"unknown owner", "unknown owner", func(m *queueManifest) { m.Allocations[0].Queue = "removed" }},
		{"missing rationale", "rationale", func(m *queueManifest) { m.Allocations[0].Rationale = " " }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, m := manifestFixture(t)
			tc.mutate(&m)
			_, err := validateManifest(root, m)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err=%v want %q", err, tc.reason)
			}
		})
	}
}

func TestManifestRequiresOwnersAndBehavioralEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*queueManifest)
	}{
		{"duplicate owner", "duplicate owner", func(m *queueManifest) { m.Owners = append(m.Owners, m.Owners[0]) }},
		{"empty owner", "owner id", func(m *queueManifest) { m.Owners[0].ID = "" }},
		{"missing rows", "health rows", func(m *queueManifest) { m.Owners[0].Rows = nil }},
		{"duplicate row", "duplicate health row", func(m *queueManifest) { m.Owners[1].Rows = m.Owners[0].Rows }},
		{"missing bounds", "bounds", func(m *queueManifest) { m.Owners[0].Bounds = "" }},
		{"missing publication", "publication evidence", func(m *queueManifest) { m.Owners[0].Publication = nil }},
		{"missing lifecycle", "lifecycle evidence", func(m *queueManifest) { m.Owners[0].Lifecycle = nil }},
		{"missing source", "source ownership", func(m *queueManifest) { m.Owners[1].Anchors = nil }},
		{"stale anchor", "source anchor", func(m *queueManifest) { m.Owners[1].Anchors[0].Symbol = "spool.removed" }},
		{"changed anchor", "source anchor changed", func(m *queueManifest) { m.Owners[1].Anchors[0].Shape = "[]int" }},
		{"unknown evidence mode", "evidence mode", func(m *queueManifest) { m.Owners[0].Lifecycle[0].Mode = "optional" }},
		{"non test name", "top-level test", func(m *queueManifest) { m.Owners[0].Publication[0].Name = "helper" }},
		{"subtest name", "top-level test", func(m *queueManifest) { m.Owners[0].Publication[0].Name = "TestPublished/case" }},
		{"foreign package", "test package", func(m *queueManifest) { m.Owners[0].Publication[0].Package = "example.test/other" }},
		{"version", "manifest version", func(m *queueManifest) { m.Version = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, m := manifestFixture(t)
			tc.mutate(&m)
			_, err := validateManifest(root, m)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err=%v want %q", err, tc.reason)
			}
		})
	}
}

func TestManifestClassifiesSignalsSeparatelyFromOwnedWork(t *testing.T) {
	for _, class := range []string{"lifecycle", "maintenance", "constructor"} {
		t.Run(class, func(t *testing.T) {
			root, m := manifestFixture(t)
			m.Allocations[0].Class = class
			m.Allocations[0].Queue = ""
			m.Owners = m.Owners[1:]
			if _, err := validateManifest(root, m); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManifestUnionsModeEvidenceWithExistingRequirements(t *testing.T) {
	root, m := manifestFixture(t)
	evidence, err := validateManifest(root, m)
	if err != nil {
		t.Fatal(err)
	}
	baseline := []requiredTest{{Package: modulePath + "/internal/example", Name: "TestBaseline"}, {Package: modulePath + "/internal/example", Name: "TestPublished"}}
	got, err := requiredTests(evidence, baseline, "portable")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, test := range got {
		names = append(names, test.Name)
	}
	if !slices.Equal(names, []string{"TestBaseline", "TestLifecycle", "TestPublished"}) {
		t.Fatalf("portable requirements=%+v", got)
	}
	got, err = requiredTests(evidence, baseline, "kernel")
	if err != nil {
		t.Fatal(err)
	}
	names = nil
	for _, test := range got {
		names = append(names, test.Name)
	}
	if !slices.Equal(names, []string{"TestBaseline", "TestKernel", "TestPublished"}) {
		t.Fatalf("kernel requirements=%+v", got)
	}
	if _, err := requiredTests(evidence, baseline, "optional"); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

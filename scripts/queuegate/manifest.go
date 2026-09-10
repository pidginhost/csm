package main

import (
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

type queueManifest struct {
	Version     int                  `json:"version"`
	Allocations []allocationDecision `json:"allocations"`
	Owners      []queueOwner         `json:"owners"`
}

type allocationDecision struct {
	allocation
	Class     string `json:"class"`
	Queue     string `json:"queue,omitempty"`
	Rationale string `json:"rationale"`
}

type queueOwner struct {
	ID          string         `json:"id"`
	Rows        []string       `json:"rows"`
	Bounds      string         `json:"bounds"`
	Anchors     []sourceAnchor `json:"anchors,omitempty"`
	Publication []testEvidence `json:"publication"`
	Lifecycle   []testEvidence `json:"lifecycle"`
}

type sourceAnchor struct {
	Path   string `json:"path"`
	Symbol string `json:"symbol"`
	Shape  string `json:"shape"`
}

type testEvidence struct {
	Package string `json:"package"`
	Name    string `json:"name"`
	Mode    string `json:"mode"`
}

// Match testgate's input so one execution verifier covers both inventories.
type requiredTest struct {
	Package string
	Name    string
	Source  string `json:",omitempty"`
}

var testName = regexp.MustCompile(`^Test([A-Z0-9_][A-Za-z0-9_]*)?$`)

func validateTest(test requiredTest) error {
	if !strings.HasPrefix(test.Package, modulePath+"/") || path.Clean(test.Package) != test.Package {
		return fmt.Errorf("invalid test package %q", test.Package)
	}
	if !testName.MatchString(test.Name) || test.Name == "TestMain" {
		return fmt.Errorf("invalid top-level test %q", test.Name)
	}
	return nil
}

func validateEvidence(owner, role string, evidence []testEvidence) error {
	if len(evidence) == 0 {
		return fmt.Errorf("owner %s needs %s evidence", owner, role)
	}
	for _, test := range evidence {
		if test.Mode != "portable" && test.Mode != "kernel" {
			return fmt.Errorf("owner %s has invalid evidence mode %q", owner, test.Mode)
		}
		if err := validateTest(requiredTest{Package: test.Package, Name: test.Name}); err != nil {
			return fmt.Errorf("owner %s: %w", owner, err)
		}
	}
	return nil
}

func validateManifest(root fs.FS, manifest queueManifest) ([]testEvidence, error) {
	if manifest.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	index, err := readSources(root)
	if err != nil {
		return nil, err
	}
	actual, err := index.allocations()
	if err != nil {
		return nil, err
	}
	owners := make(map[string]queueOwner)
	rows := make(map[string]string)
	var evidence []testEvidence
	for _, owner := range manifest.Owners {
		if strings.TrimSpace(owner.ID) == "" {
			return nil, fmt.Errorf("empty owner id")
		}
		if _, exists := owners[owner.ID]; exists {
			return nil, fmt.Errorf("duplicate owner %s", owner.ID)
		}
		owners[owner.ID] = owner
		if len(owner.Rows) == 0 {
			return nil, fmt.Errorf("owner %s needs health rows", owner.ID)
		}
		for _, row := range owner.Rows {
			if strings.TrimSpace(row) == "" {
				return nil, fmt.Errorf("owner %s has empty health rows", owner.ID)
			}
			if previous, exists := rows[row]; exists {
				return nil, fmt.Errorf("duplicate health row %s in %s and %s", row, previous, owner.ID)
			}
			rows[row] = owner.ID
		}
		if strings.TrimSpace(owner.Bounds) == "" {
			return nil, fmt.Errorf("owner %s needs reviewed bounds", owner.ID)
		}
		if err := validateEvidence(owner.ID, "publication", owner.Publication); err != nil {
			return nil, err
		}
		if err := validateEvidence(owner.ID, "lifecycle", owner.Lifecycle); err != nil {
			return nil, err
		}
		for _, anchor := range owner.Anchors {
			if err := index.validateAnchor(anchor); err != nil {
				return nil, fmt.Errorf("owner %s: %w", owner.ID, err)
			}
		}
		evidence = append(evidence, owner.Publication...)
		evidence = append(evidence, owner.Lifecycle...)
	}
	live := make(map[string]allocation)
	for _, site := range actual {
		live[site.ID] = site
	}
	reviewed := make(map[string]bool)
	owned := make(map[string]bool)
	for _, decision := range manifest.Allocations {
		if reviewed[decision.ID] {
			return nil, fmt.Errorf("duplicate allocation %s", decision.ID)
		}
		reviewed[decision.ID] = true
		current, exists := live[decision.ID]
		if !exists {
			return nil, fmt.Errorf("stale allocation %s", decision.ID)
		}
		if !sameAllocation(current, decision.allocation) {
			return nil, fmt.Errorf("allocation changed: %s", decision.ID)
		}
		if strings.TrimSpace(decision.Rationale) == "" {
			return nil, fmt.Errorf("allocation %s needs a rationale", decision.ID)
		}
		switch decision.Class {
		case "work":
			if decision.Queue == "" {
				return nil, fmt.Errorf("work allocation needs an owner: %s", decision.ID)
			}
			owned[decision.Queue] = true
		case "lifecycle", "maintenance", "constructor":
		default:
			return nil, fmt.Errorf("unknown allocation class %q: %s", decision.Class, decision.ID)
		}
		if decision.Queue != "" {
			if _, exists := owners[decision.Queue]; !exists {
				return nil, fmt.Errorf("allocation %s has unknown owner %s", decision.ID, decision.Queue)
			}
		}
	}
	for _, site := range actual {
		if !reviewed[site.ID] {
			return nil, fmt.Errorf("unclassified allocation %s", site.ID)
		}
	}
	for _, owner := range manifest.Owners {
		if !owned[owner.ID] && len(owner.Anchors) == 0 {
			return nil, fmt.Errorf("owner %s needs source ownership: a work allocation or source anchor", owner.ID)
		}
	}
	return evidence, nil
}

func sameAllocation(left, right allocation) bool {
	if !slices.Equal(left.Defaults, right.Defaults) {
		return false
	}
	left.Defaults, right.Defaults = nil, nil
	return reflect.DeepEqual(left, right)
}

func requiredTests(evidence []testEvidence, baseline []requiredTest, mode string) ([]requiredTest, error) {
	if mode != "portable" && mode != "kernel" {
		return nil, fmt.Errorf("unknown evidence mode %q", mode)
	}
	unique := make(map[requiredTest]bool)
	for _, test := range baseline {
		if err := validateTest(test); err != nil {
			return nil, err
		}
		test.Source = ""
		unique[test] = true
	}
	for _, test := range evidence {
		if test.Mode == mode {
			unique[requiredTest{Package: test.Package, Name: test.Name}] = true
		}
	}
	result := make([]requiredTest, 0, len(unique))
	for test := range unique {
		result = append(result, test)
	}
	slices.SortFunc(result, func(a, b requiredTest) int {
		if n := strings.Compare(a.Package, b.Package); n != 0 {
			return n
		}
		return strings.Compare(a.Name, b.Name)
	})
	return result, nil
}

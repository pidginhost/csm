package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

// The phpanel agent runs `csm capabilities` before rendering newer config
// keys, so it has to answer without a daemon or a readable config.
func TestCapabilitiesCommandPrintsOnePerLine(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, nil); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if want := health.Capabilities(); !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestCapabilitiesCommandJSON(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, []string{"--config", "/missing/csm.yaml", "--json"}); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not a JSON array: %v: %s", err, out.String())
	}
	if want := health.Capabilities(); !slices.Equal(got, want) {
		t.Fatalf("capabilities = %q, want %q", got, want)
	}
}

func TestCapabilitiesCommandRejectsUnknownFlag(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, []string{"--yaml"}); err == nil {
		t.Fatal("unknown flag must fail")
	}
	if out.Len() != 0 {
		t.Fatalf("nothing may be printed on a usage error, got %q", out.String())
	}
}

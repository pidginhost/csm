package config

import (
	"encoding/json"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSchema_TopLevelKeys(t *testing.T) {
	schema := Schema()
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("expected top-level properties map")
	}
	for _, want := range []string{"hostname", "state_path", "alerts", "webui"} {
		if _, ok := props[want]; !ok {
			t.Fatalf("expected schema to include %q, got keys %v", want, schemaKeysOf(props))
		}
	}
}

func TestSchema_StateDirIsString(t *testing.T) {
	schema := Schema()
	props := schema["properties"].(map[string]interface{})
	state := props["state_path"].(map[string]interface{})
	if state["type"] != "string" {
		t.Fatalf("expected state_path.type=string, got %v", state["type"])
	}
}

func TestSchema_RoundTripsAsJSON(t *testing.T) {
	b, err := json.Marshal(Schema())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
}

func TestSchema_DoesNotMarkDefaultedFieldsRequired(t *testing.T) {
	schema := Schema()
	if _, ok := schema["required"]; ok {
		t.Fatalf("schema must not mark defaulted config fields required: %v", schema["required"])
	}
}

func TestSchema_DurationFieldsAreStrings(t *testing.T) {
	schema := Schema()
	props := schema["properties"].(map[string]interface{})
	challenge := props["challenge"].(map[string]interface{})["properties"].(map[string]interface{})
	captcha := challenge["captcha_fallback"].(map[string]interface{})["properties"].(map[string]interface{})
	timeout := captcha["timeout"].(map[string]interface{})
	if timeout["type"] != "string" {
		t.Fatalf("duration field timeout.type = %v, want string", timeout["type"])
	}
	if timeout["format"] != "duration" {
		t.Fatalf("duration field timeout.format = %v, want duration", timeout["format"])
	}
}

// TestSchema_DefaultConfigValidatesAgainstSchema is a smoke test: every
// top-level key the shipped default config sets MUST appear in the
// generated schema's properties. Catches drift when a field is added to
// Config without a yaml tag, or when a yaml tag changes case/format.
func TestSchema_DefaultConfigValidatesAgainstSchema(t *testing.T) {
	defaultBytes, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Skipf("default config not readable from this layout: %v", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(defaultBytes, &raw); err != nil {
		t.Fatal(err)
	}
	schema := Schema()
	props := schema["properties"].(map[string]interface{})
	for key := range raw {
		if _, ok := props[key]; !ok {
			t.Errorf("default config has key %q that the schema doesn't advertise", key)
		}
	}
}

func schemaKeysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

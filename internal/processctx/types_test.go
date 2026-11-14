package processctx

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProcessContextJSONOmitsZeroFields(t *testing.T) {
	pc := ProcessContext{PID: 1234, PPID: 1, UID: 1001}
	b, err := json.Marshal(pc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{"user", "account", "comm", "exe", "cmdline", "started_at", "parent"} {
		if strings.Contains(s, `"`+key+`"`) {
			t.Errorf("zero-value ProcessContext should omit %q, got %s", key, s)
		}
	}
	if !strings.Contains(s, `"pid":1234`) || !strings.Contains(s, `"uid":1001`) {
		t.Errorf("required fields missing: %s", s)
	}
}

func TestProcessContextJSONIncludesPopulatedFields(t *testing.T) {
	startedAt := time.Unix(1700000000, 0).UTC()
	pc := ProcessContext{
		PID:       1234,
		PPID:      1,
		UID:       1001,
		User:      "alice",
		Account:   "alice",
		Comm:      "ncat",
		Exe:       "/usr/bin/ncat",
		Cmdline:   []string{"ncat", "203.0.113.10", "587"},
		StartedAt: &startedAt,
		Parent:    &ProcessContext{PID: 1, Comm: "init"},
	}
	b, err := json.Marshal(pc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"user":"alice"`, `"account":"alice"`, `"exe":"/usr/bin/ncat"`, `"parent":{`, `"comm":"init"`} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in %s", want, s)
		}
	}
}

func TestProcessEntryHasNoExportedJSONTags(t *testing.T) {
	// processEntry is the cache shape; it must not be marshaled directly.
	// Public callers only ever see ProcessContext, so a json tag here means
	// someone started serializing the cache.
	typ := reflect.TypeOf(processEntry{})
	if typ.NumField() == 0 {
		t.Fatal("processEntry has no fields to check")
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if tag, ok := f.Tag.Lookup("json"); ok {
			t.Errorf("processEntry.%s carries json tag %q", f.Name, tag)
		}
	}
}

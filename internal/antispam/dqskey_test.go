package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const testKey = "abcdefghijklmnopqrstu23456"

func TestSecretNeverPrints(t *testing.T) {
	s := defaults(false)
	s.DQSKey = NewSecret(testKey)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{
		fmt.Sprintf("%v %+v %#v %s", s, s, s, s.DQSKey), string(data),
		fmt.Sprint(s.DQSKey), fmt.Sprintf("%q", s.DQSKey),
	} {
		if strings.Contains(out, testKey) {
			t.Fatalf("key leaked: %s", out)
		}
	}
	if s.DQSKey.Reveal() != testKey {
		t.Fatal("Reveal must return the key")
	}
}

func TestSecretFormattingFallbacks(t *testing.T) {
	s := defaults(false)
	s.DQSKey = NewSecret(testKey)
	for name, value := range map[string]any{
		"secret":   s.DQSKey,
		"pointer":  &s.DQSKey,
		"settings": s,
		"slice":    []Secret{s.DQSKey},
		"map key":  map[Secret]bool{s.DQSKey: true},
		"private":  struct{ key Secret }{s.DQSKey},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p", "%w"} {
				out := fmt.Sprintf(format, value)
				for _, key := range []string{testKey, fmt.Sprintf("%x", testKey), fmt.Sprintf("%X", testKey)} {
					if strings.Contains(out, key) {
						t.Errorf("%s exposed the key", format)
					}
				}
			}
		})
	}
}

func TestSecretEmpty(t *testing.T) {
	for _, key := range []Secret{{}, NewSecret("")} {
		if key.Reveal() != "" || key.String() != redacted {
			t.Fatal("empty key must reveal as empty and print as redacted")
		}
		data, err := json.Marshal(key)
		if err != nil || string(data) != `"[redacted]"` {
			t.Fatalf("empty key JSON is not redacted: %v", err)
		}
	}
}

func TestSecretJSONMapKey(t *testing.T) {
	data, err := json.Marshal(map[Secret]bool{NewSecret(testKey): true})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"[redacted]":true}` {
		t.Fatal("JSON map key was not redacted")
	}
}

func TestLoadDQSKey(t *testing.T) {
	ok := KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: NewSecret(testKey)}
	if key, err := LoadDQSKey(ok); err != nil || key.Reveal() != testKey {
		t.Fatalf("valid key: %v", err)
	}
	for name, k := range map[string]KeyFacts{
		"missing":      {Path: "/etc/csm/k", Missing: true},
		"unreadable":   {Path: "/etc/csm/k", Err: errors.New("boom")},
		"not root":     {Path: "/etc/csm/k", UID: 1000, Mode: 0o600, Key: NewSecret(testKey)},
		"group write":  {Path: "/etc/csm/k", Mode: 0o620, Key: NewSecret(testKey)},
		"world read":   {Path: "/etc/csm/k", Mode: 0o604, Key: NewSecret(testKey)},
		"short":        {Path: "/etc/csm/k", Mode: 0o600, Key: NewSecret(testKey[:25])},
		"uppercase":    {Path: "/etc/csm/k", Mode: 0o600, Key: NewSecret(strings.ToUpper(testKey))},
		"quote inside": {Path: "/etc/csm/k", Mode: 0o600, Key: NewSecret(`abcdefghijklmnopqrstu2345"`)},
	} {
		key, err := LoadDQSKey(k)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if key.Reveal() != "" {
			t.Errorf("%s: returned a key after rejection", name)
		}
		if strings.Contains(err.Error(), testKey[:20]) {
			t.Errorf("%s: error carries the key: %v", name, err)
		}
	}
}

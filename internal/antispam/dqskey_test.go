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
	s.DQSKey = Secret(testKey)
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

func TestLoadDQSKey(t *testing.T) {
	ok := KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: Secret(testKey)}
	if key, err := LoadDQSKey(ok); err != nil || key.Reveal() != testKey {
		t.Fatalf("valid key: %v", err)
	}
	for name, k := range map[string]KeyFacts{
		"missing":      {Path: "/etc/csm/k", Missing: true},
		"unreadable":   {Path: "/etc/csm/k", Err: errors.New("boom")},
		"not root":     {Path: "/etc/csm/k", UID: 1000, Mode: 0o600, Key: Secret(testKey)},
		"group write":  {Path: "/etc/csm/k", Mode: 0o620, Key: Secret(testKey)},
		"world read":   {Path: "/etc/csm/k", Mode: 0o604, Key: Secret(testKey)},
		"short":        {Path: "/etc/csm/k", Mode: 0o600, Key: Secret(testKey[:25])},
		"uppercase":    {Path: "/etc/csm/k", Mode: 0o600, Key: Secret(strings.ToUpper(testKey))},
		"quote inside": {Path: "/etc/csm/k", Mode: 0o600, Key: Secret(`abcdefghijklmnopqrstu2345"`)},
	} {
		_, err := LoadDQSKey(k)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), testKey[:20]) {
			t.Errorf("%s: error carries the key: %v", name, err)
		}
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAntispamLearnFreshNamespace(t *testing.T) {
	saved, savedEUID := learnFreshSend, antispamEUID
	t.Cleanup(func() { learnFreshSend, antispamEUID = saved, savedEUID })
	antispamEUID = func() int { return 0 }
	calls := 0
	learnFreshSend = func() (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"archived":"/var/lib/csm/antispam/learning.old-20261019T120000Z"}`), nil
	}
	var out, errOut bytes.Buffer
	if code := antispamLearn([]string{"--fresh-namespace"}, &out, &errOut); code != 0 || calls != 1 {
		t.Fatalf("exit %d, calls %d, stderr %s", code, calls, errOut.String())
	}
	if !strings.Contains(out.String(), "learning.old-20261019T120000Z") {
		t.Fatalf("output %q", out.String())
	}
	if code := antispamLearn([]string{"--fresh-namespace", "mail.eml"}, &out, &errOut); code != 2 || calls != 1 {
		t.Fatalf("files accepted with --fresh-namespace: exit %d", code)
	}
	learnFreshSend = func() (json.RawMessage, error) { return nil, errors.New("disable antispam learning first") }
	errOut.Reset()
	if code := antispamLearn([]string{"--fresh-namespace"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "disable") {
		t.Fatalf("refusal: exit %d, stderr %q", code, errOut.String())
	}
}

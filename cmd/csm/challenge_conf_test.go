package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/challenge"
)

const legacyChallengeMapName = "csm_challenge"

func TestLegacyChallengeConfRewriteMapPathMatchesDaemonDefault(t *testing.T) {
	data, err := os.ReadFile("../../configs/csm_challenge.conf")
	if err != nil {
		t.Fatalf("read challenge conf: %v", err)
	}
	matches := regexp.MustCompile(`(?m)^\s*RewriteMap\s+(\S+)\s+"?txt:([^"\s]+)"?`).FindAllSubmatch(data, -1)
	var got string
	var found bool
	for _, m := range matches {
		if string(m[1]) != legacyChallengeMapName {
			continue
		}
		if found {
			t.Fatalf("duplicate RewriteMap %s directive found in challenge conf", legacyChallengeMapName)
		}
		got = string(m[2])
		found = true
	}
	if !found {
		t.Fatalf("no RewriteMap %s txt: directive found in challenge conf:\n%s", legacyChallengeMapName, data)
	}
	if got != challenge.DefaultMapPath {
		t.Errorf("challenge conf RewriteMap %s path = %q, want %q",
			legacyChallengeMapName,
			got, challenge.DefaultMapPath)
	}

	body := string(data)
	if !strings.Contains(body, "RewriteCond ${"+legacyChallengeMapName+":%{REMOTE_ADDR}} =challenge") {
		t.Errorf("challenge conf must look up %s in the rewrite condition", legacyChallengeMapName)
	}
	if !regexp.MustCompile(`(?m)^\s*RewriteRule\s+\^\(\.\*\)\$\s+\S+\s+\[P,L\]\s*$`).Match(data) {
		t.Errorf("legacy challenge conf must keep proxy mode [P,L]")
	}
}

package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// whmTokensJSON builds a whmapi1 api_token_list --output=json payload from a
// name -> all-acl map. all=true sets the full-access "all" ACL to 1.
func whmTokensJSON(tokens map[string]bool) string {
	var b strings.Builder
	b.WriteString(`{"data":{"tokens":{`)
	first := true
	for name, all := range tokens {
		if !first {
			b.WriteByte(',')
		}
		first = false
		v := 0
		if all {
			v = 1
		}
		b.WriteString(`"`)
		b.WriteString(name)
		b.WriteString(`":{"acls":{"all":`)
		if v == 1 {
			b.WriteString("1")
		} else {
			b.WriteString("0")
		}
		b.WriteString(`},"create_time":"1700000000","expires_at":null}`)
	}
	b.WriteString(`}}}`)
	return b.String()
}

// runWHMTokens seeds the prior token state, feeds the current token list via the
// mocked whmapi1 command, and returns the WHM-root api_tokens findings.
func runWHMTokens(t *testing.T, prior, current map[string]bool) []alert.Finding {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if prior != nil {
		store.SetRaw(whmAPITokensStateKey, marshalTokenSig(tokenSigFromMap(prior)))
	}

	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	withMockCmd(t, &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "whmapi1" {
				return []byte(whmTokensJSON(current)), nil
			}
			return nil, nil
		},
	})

	var whm []alert.Finding
	for _, f := range CheckAPITokens(context.Background(), &config.Config{}, store) {
		if f.Check == "api_tokens" && strings.Contains(f.Message, "WHM root") {
			whm = append(whm, f)
		}
	}
	return whm
}

// tokenSigFromMap is the test-side mirror of how the detector records prior
// state, so a seeded baseline matches what a previous scan would have stored.
func tokenSigFromMap(m map[string]bool) tokenSig {
	sig := tokenSig{}
	for name, all := range m {
		sig[name] = tokenInfo{
			FullAccess:     all,
			ClusterManaged: !all && (strings.HasPrefix(name, "reverse_trust_") || strings.HasSuffix(name, "-trust")),
		}
	}
	return sig
}

func TestWHMTokens_FirstRunBaselineNoFinding(t *testing.T) {
	got := runWHMTokens(t, nil, map[string]bool{"phclient": true})
	if len(got) != 0 {
		t.Fatalf("first run must set baseline silently, got %+v", got)
	}
}

func TestWHMTokens_NoChangeNoFinding(t *testing.T) {
	set := map[string]bool{"phclient": true, "ns2-trust": false}
	got := runWHMTokens(t, set, set)
	if len(got) != 0 {
		t.Fatalf("unchanged token set must not alert, got %+v", got)
	}
}

func TestWHMTokens_ClusterChurnOnlyWarning(t *testing.T) {
	prior := map[string]bool{
		"phclient":               true,
		"reverse_trust_aaaaaaaa": false,
		"reverse_trust_bbbbbbbb": false,
	}
	// One reverse_trust token recreated under a new UUID; cPanel DNS clustering
	// does this on its own. Must NOT page as Critical.
	current := map[string]bool{
		"phclient":               true,
		"reverse_trust_aaaaaaaa": false,
		"reverse_trust_cccccccc": false,
	}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 {
		t.Fatalf("cluster churn must yield exactly one finding, got %+v", got)
	}
	if got[0].Severity != alert.Warning {
		t.Errorf("cluster trust churn must be Warning, got %v", got[0].Severity)
	}
	if !strings.Contains(got[0].Details, "reverse_trust_cccccccc") {
		t.Errorf("finding must name the changed cluster token, got %q", got[0].Details)
	}
}

func TestWHMTokens_NewManualTokenCritical(t *testing.T) {
	prior := map[string]bool{"phclient": true}
	current := map[string]bool{"phclient": true, "attacker": false}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("new non-cluster token must be Critical, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "attacker") {
		t.Errorf("finding must name the added token, got %q", got[0].Details)
	}
}

func TestWHMTokens_NewTrustSuffixWithoutClusterACLCritical(t *testing.T) {
	prior := map[string]bool{"phclient": true}
	current := map[string]bool{"phclient": true, "x-trust": false}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("attacker-named trust token must be Critical, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "x-trust") {
		t.Errorf("finding must name the added token, got %q", got[0].Details)
	}
}

func TestWHMTokens_NewTrustSuffixWithClusterACLCritical(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetRaw(whmAPITokensStateKey, marshalTokenSig(tokenSigFromMap(map[string]bool{"phclient": true})))

	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	withMockCmd(t, &mockCmd{
		run: func(name string, _ ...string) ([]byte, error) {
			if name != "whmapi1" {
				return nil, nil
			}
			return []byte(`{"data":{"tokens":{` +
				`"phclient":{"acls":{"all":1}},` +
				`"x-trust":{"acls":{"all":0,"clustering":1}}` +
				`}}}`), nil
		},
	})

	got := CheckAPITokens(context.Background(), &config.Config{}, store)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("new trust-suffix token must be Critical even with cluster ACL, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "x-trust") {
		t.Errorf("finding must name the added token, got %q", got[0].Details)
	}
}

func TestWHMTokens_NewFullAccessTokenCritical(t *testing.T) {
	prior := map[string]bool{"phclient": true}
	current := map[string]bool{"phclient": true, "rogue": true}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("new full-access token must be Critical, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "rogue") {
		t.Errorf("finding must name the full-access token, got %q", got[0].Details)
	}
}

func TestWHMTokens_EscalationToFullAccessCritical(t *testing.T) {
	// A cluster trust token quietly gaining the "all" ACL is an escalation, not
	// benign churn -- must be Critical even though the name is cluster-managed.
	prior := map[string]bool{"phclient": true, "ns2-trust": false}
	current := map[string]bool{"phclient": true, "ns2-trust": true}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("ACL escalation must be Critical, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "ns2-trust") {
		t.Errorf("finding must name the escalated token, got %q", got[0].Details)
	}
}

func TestWHMTokens_RemovedManualTokenCritical(t *testing.T) {
	prior := map[string]bool{"phclient": true, "ci-deploy": false}
	current := map[string]bool{"phclient": true}
	got := runWHMTokens(t, prior, current)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("removed non-cluster token must be Critical, got %+v", got)
	}
	if !strings.Contains(got[0].Details, "ci-deploy") {
		t.Errorf("finding must name the removed token, got %q", got[0].Details)
	}
}

func TestWHMTokens_DecodesAllACLNumberStringAndBool(t *testing.T) {
	out := []byte(`{"data":{"tokens":{` +
		`"number":{"acls":{"all":1}},` +
		`"string":{"acls":{"all":"1"}},` +
		`"bool":{"acls":{"all":true}},` +
		`"zero":{"acls":{"all":0}}` +
		`}}}`)
	got, ok := parseWHMTokenSig(out)
	if !ok {
		t.Fatal("expected WHM token payload to parse")
	}
	for _, name := range []string{"number", "string", "bool"} {
		if !got[name].FullAccess {
			t.Errorf("%s all ACL was not decoded as full access", name)
		}
	}
	if got["zero"].FullAccess {
		t.Error("zero all ACL decoded as full access")
	}
}

func TestWHMTokens_FallbackHashOnJSONParseFailure(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetRaw(whmAPITokensHashKey, hashBytes([]byte("old raw output")))

	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" {
				return nil, nil
			}
			if len(args) == 2 && args[1] == "--output=json" {
				return []byte("api_token_list: unknown option --output"), nil
			}
			return []byte("new raw output"), nil
		},
	})

	got := CheckAPITokens(context.Background(), &config.Config{}, store)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("legacy hash fallback must alert on changed raw output, got %+v", got)
	}
	if _, exists := store.GetRaw(whmAPITokensStateKey); exists {
		t.Fatal("malformed JSON output must not replace structured WHM token state")
	}
}

func TestWHMTokens_FallbackHashWhenJSONCommandFails(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetRaw(whmAPITokensHashKey, hashBytes([]byte("old raw output")))

	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" {
				return nil, nil
			}
			if len(args) == 2 && args[1] == "--output=json" {
				return nil, errors.New("unknown option")
			}
			return []byte("new raw output"), nil
		},
	})

	got := CheckAPITokens(context.Background(), &config.Config{}, store)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("legacy hash fallback must alert when JSON command fails, got %+v", got)
	}
}

func TestWHMTokens_LegacyHashCheckedBeforeStructuredBaseline(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetRaw(whmAPITokensHashKey, hashBytes([]byte("old raw output")))

	withMockOS(t, &mockOS{glob: func(string) ([]string, error) { return nil, nil }})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name != "whmapi1" {
				return nil, nil
			}
			if len(args) == 2 && args[1] == "--output=json" {
				return []byte(whmTokensJSON(map[string]bool{"phclient": true})), nil
			}
			return []byte("new raw output"), nil
		},
	})

	got := CheckAPITokens(context.Background(), &config.Config{}, store)
	if len(got) != 1 || got[0].Severity != alert.Critical {
		t.Fatalf("legacy hash change must not be hidden by structured baseline, got %+v", got)
	}
	if _, exists := store.GetRaw(whmAPITokensStateKey); !exists {
		t.Fatal("successful structured parse must still seed structured state")
	}
}

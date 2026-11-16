package stalwartsetup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/stalwartapi"
)

// TestSmokeAgainstStalwart runs setup against a real, throwaway Stalwart, then
// acts through CSM's role. It needs a fresh server: a second run finds the
// accounts the first one made. It skips unless CSM_STALWART_SMOKE_URL names
// one; STALWART_USER and STALWART_PASSWORD carry its admin login. A stock
// install binds its HTTP listeners on every address, so the client address
// step must be skipped. Setup's key works only from this host, so the cases
// that act through a key need CSM_STALWART_SMOKE_CLIENT_IP: the address
// Stalwart sees this test connect from, which a second key of CSM's account
// is limited to.
func TestSmokeAgainstStalwart(t *testing.T) {
	url := os.Getenv("CSM_STALWART_SMOKE_URL")
	if url == "" {
		t.Skip("CSM_STALWART_SMOKE_URL is not set")
	}
	ctx := context.Background()
	user, password := os.Getenv("STALWART_USER"), os.Getenv("STALWART_PASSWORD")
	api := stalwartapi.New(url, user, password)
	var setupKey string
	in := Inputs{BlockExpiry: 24 * time.Hour, LocalAPI: true, WriteKey: func(secret string) error {
		setupKey = secret
		return nil
	}}

	p, err := Inspect(ctx, api, in)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	warnings, err := p.Apply(ctx, api)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Logf("reload warnings: %q", warnings)
	if setupKey == "" {
		t.Fatal("Apply stored no key")
	}

	accounts, err := api.AccountsNamed(ctx, ResponseAccount)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("AccountsNamed(%q) = %d accounts, %v; want 1", ResponseAccount, len(accounts), err)
	}
	responseID := accounts[0].ID
	role, found, err := api.RoleByDescription(ctx, ResponseRole)
	if err != nil || !found {
		t.Fatalf("RoleByDescription(%q) = %v, %v", ResponseRole, found, err)
	}

	in.KeyAccount = responseID
	p, err = Inspect(ctx, api, in)
	if err != nil {
		t.Fatalf("second Inspect: %v", err)
	}
	want := []State{Done, Skipped, Done, Done, Done, Done, Done, Done, Done}
	if len(p.Steps) != len(want) {
		t.Fatalf("second Inspect has %d steps, want %d", len(p.Steps), len(want))
	}
	for i, s := range p.Steps {
		t.Logf("%s: %s: %s", s.Name, s.State, s.Detail)
		if s.State != want[i] {
			t.Errorf("%s = %s, want %s", s.Name, s.State, want[i])
		}
	}

	// Docker's proxy holds the published port, which the production peer
	// check refuses.
	anyPeer := func(context.Context, net.Conn) error { return nil }
	if _, err = stalwartapi.NewKey(url, setupKey, anyPeer).SessionAccount(ctx); !errors.Is(err, stalwartapi.ErrForbidden) {
		t.Fatalf("setup's key from this test's address: %v, want ErrForbidden", err)
	}

	clientIP := os.Getenv("CSM_STALWART_SMOKE_CLIENT_IP")
	if clientIP == "" {
		t.Skip("CSM_STALWART_SMOKE_CLIENT_IP is not set; the cases that act through CSM's key need the address Stalwart sees this test connect from")
	}
	_, secret, err := api.CreateAPIKey(ctx, responseID, "CSM smoke test", []string{clientIP})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	key := stalwartapi.NewKey(url, secret, anyPeer)
	if id, keyErr := key.SessionAccount(ctx); keyErr != nil || id != responseID {
		t.Fatalf("key session account = %q, %v; want CSM's account %q", id, keyErr, responseID)
	}

	adminID, err := api.SessionAccount(ctx)
	if err != nil {
		t.Fatalf("admin SessionAccount: %v", err)
	}
	asAdmin := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	domains, err := api.Domains(ctx)
	if err != nil {
		t.Fatalf("Domains: %v", err)
	}
	i := slices.IndexFunc(domains, func(d stalwartapi.Domain) bool { return d.Name == "example.org" })
	if i < 0 {
		t.Fatalf("Stalwart has no domain example.org: %v", domains)
	}
	domainID := domains[i].ID
	userPassword := rand.Text()
	if err = jmapSet(ctx, url, asAdmin, adminID, "x:Account/set", map[string]any{"create": map[string]any{"u": map[string]any{
		"@type":       "User",
		"name":        "smoke",
		"domainId":    domainID,
		"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": userPassword}},
		"aliases":     map[string]any{"0": map[string]any{"name": "smoke-alias", "domainId": domainID, "enable": true}},
	}}}); err != nil {
		t.Fatalf("creating the test account: %v", err)
	}
	if err = jmapSet(ctx, url, asAdmin, adminID, "x:Domain/set", map[string]any{"update": map[string]any{
		domainID: map[string]any{"aliases": map[string]any{"example.net": true}},
	}}); err != nil {
		t.Fatalf("adding the domain alias: %v", err)
	}
	smoke, err := api.AccountsNamed(ctx, "smoke")
	if err != nil || len(smoke) != 1 {
		t.Fatalf("AccountsNamed(smoke) = %d accounts, %v; want 1", len(smoke), err)
	}
	smokeID := smoke[0].ID

	t.Run("sign-in", func(t *testing.T) {
		a, found, err := key.AccountByAddress(ctx, "smoke@example.org")
		if err != nil || !found || a.ID != smokeID {
			t.Fatalf("AccountByAddress = %q, %v, %v; want %q", a.ID, found, err, smokeID)
		}
		// A client reads its session once, so each login needs a new one.
		login := func() error {
			_, err := stalwartapi.New(url, "smoke@example.org", userPassword).SessionAccount(ctx)
			return err
		}
		if err := login(); err != nil {
			t.Fatalf("login before DisableSignIn: %v", err)
		}
		// The second round starts from the permissions the first release
		// left: an empty Merge, which the path patch must still work on.
		for round := 1; round <= 2; round++ {
			if round == 2 {
				var readErr error
				if a, _, readErr = key.Account(ctx, smokeID); readErr != nil {
					t.Fatalf("round %d: Account: %v", round, readErr)
				}
			}
			if err := key.DisableSignIn(ctx, a); err != nil {
				t.Fatalf("round %d: DisableSignIn: %v", round, err)
			}
			if err := login(); !errors.Is(err, stalwartapi.ErrForbidden) {
				t.Fatalf("round %d: login after DisableSignIn: %v, want ErrForbidden", round, err)
			}
			if err := key.EnableSignIn(ctx, a.ID); err != nil {
				t.Fatalf("round %d: EnableSignIn: %v", round, err)
			}
			if err := login(); err != nil {
				t.Fatalf("round %d: login after EnableSignIn: %v", round, err)
			}
		}
	})

	t.Run("aliases", func(t *testing.T) {
		for _, address := range []string{"smoke-alias@example.org", "smoke@example.net", "smoke-alias@example.net"} {
			a, found, err := key.AccountByAddress(ctx, address)
			if err != nil || !found || a.ID != smokeID {
				t.Errorf("AccountByAddress(%s) = %q, %v, %v; want %q", address, a.ID, found, err, smokeID)
			}
		}
	})

	t.Run("ban", func(t *testing.T) {
		const address = "203.0.113.9"
		if err := jmapSet(ctx, url, asAdmin, adminID, "x:BlockedIp/set", map[string]any{"create": map[string]any{
			"b": map[string]any{"address": address},
		}}); err != nil {
			t.Fatalf("creating the ban: %v", err)
		}
		bans, err := key.BlockedIPs(ctx, address)
		if err != nil || len(bans) != 1 || bans[0].Address != address || bans[0].Reason != "manual" {
			t.Fatalf("BlockedIPs = %+v, %v; want one manual ban on %s", bans, err, address)
		}
		if err := key.DeleteBlockedIPs(ctx, []string{bans[0].ID}); err != nil {
			t.Fatalf("DeleteBlockedIPs: %v", err)
		}
		if bans, err := key.BlockedIPs(ctx, address); err != nil || len(bans) != 0 {
			t.Fatalf("BlockedIPs after delete = %+v, %v; want none", bans, err)
		}
	})

	var admin stalwartapi.Account
	t.Run("admin cannot be suspended", func(t *testing.T) {
		var found bool
		var err error
		admin, found, err = key.AccountByAddress(ctx, "admin@example.org")
		if err != nil || !found {
			t.Fatalf("AccountByAddress(admin) = %v, %v", found, err)
		}
		err = key.DisableSignIn(ctx, admin)
		var me *stalwartapi.MethodError
		if !errors.As(err, &me) || me.Type != "forbidden" {
			t.Fatalf("DisableSignIn(admin) = %v, want a forbidden method error", err)
		}
		t.Logf("refused: %v", err)
		if a, found, err := api.Account(ctx, admin.ID); err != nil || !found || a.SignInDisabled {
			t.Fatalf("admin after the refusal = %+v, %v, %v; want sign-in allowed", a, found, err)
		}
	})

	t.Run("setup reads", func(t *testing.T) {
		kp, err := Inspect(ctx, key, Inputs{BlockExpiry: 24 * time.Hour, LocalAPI: true, KeyAccount: responseID})
		if err != nil {
			t.Fatalf("Inspect through the key: %v", err)
		}
		for _, s := range kp.Steps {
			t.Logf("%s: %s: %s", s.Name, s.State, s.Detail)
		}
		if got := stepStates(kp, "response role", "response account"); got != "done done" {
			t.Errorf("response role and account through the key = %s, want done done", got)
		}
		// Inspect turns a refused spam filter read into a warning, so those
		// reads are checked on their own.
		if _, err := key.SpamSettings(ctx); err != nil {
			t.Errorf("SpamSettings through the key: %v", err)
		}
		if _, err := key.SpamFilterStageOff(ctx); err != nil {
			t.Errorf("SpamFilterStageOff through the key: %v", err)
		}
	})

	t.Run("no escalation", func(t *testing.T) {
		if admin.ID == "" {
			t.Skip("the admin account was not found")
		}
		var me *stalwartapi.MethodError
		keys, err := key.APIKeys(ctx, admin.ID)
		if !errors.As(err, &me) || (me.Type != "accountNotFound" && me.Type != "forbidden") {
			t.Errorf("APIKeys(admin) through the key = %d keys, %v; want accountNotFound or forbidden", len(keys), err)
		}
		t.Logf("APIKeys(admin) refused: %v", err)
		asKey := "Bearer " + secret
		err = jmapSet(ctx, url, asKey, responseID, "x:Account/set", map[string]any{"update": map[string]any{
			responseID: map[string]any{"roles": map[string]any{"@type": "Admin"}},
		}})
		if !errors.As(err, &me) || me.Type != "forbidden" {
			t.Errorf("giving CSM's account the Admin role through the key = %v, want a forbidden method error", err)
		}
		if roles, err := api.AccountRoleIDs(ctx, responseID); err != nil || !slices.Equal(roles, []string{role.ID}) {
			t.Errorf("CSM's account roles = %v, %v; want only %q", roles, err, role.ID)
		}
	})

	// Last: it leaves CSM's account unusable for setup.
	t.Run("password refused", func(t *testing.T) {
		if err := jmapSet(ctx, url, asAdmin, adminID, "x:Account/set", map[string]any{"update": map[string]any{
			responseID: map[string]any{"credentials/9": map[string]any{"@type": "Password", "secret": rand.Text()}},
		}}); err != nil {
			t.Fatalf("adding a password to CSM's account: %v", err)
		}
		kp, err := Inspect(ctx, key, Inputs{BlockExpiry: 24 * time.Hour, LocalAPI: true, KeyAccount: responseID})
		if err != nil {
			t.Fatalf("Inspect through the key: %v", err)
		}
		if got := stepStates(kp, "response account", "response key"); got != "warn skipped" {
			t.Errorf("response account and key = %s, want warn skipped", got)
		}
		for _, s := range kp.Steps {
			if s.Name == "response account" && !strings.Contains(s.Detail, "has a password") {
				t.Errorf("response account detail = %q, want it to name the password", s.Detail)
			}
		}
	})
}

// stepStates returns the states of the named steps, space separated.
func stepStates(p Plan, names ...string) string {
	states := make([]string, len(names))
	for _, s := range p.Steps {
		if i := slices.Index(names, s.Name); i >= 0 {
			states[i] = string(s.State)
		}
	}
	return strings.Join(states, " ")
}

// jmapSet sends one /set call as auth, for fixtures the client has no call
// for and for writes it never makes. A failure carries its type only: a
// description may quote a secret from the request.
func jmapSet(ctx context.Context, url, auth, account, method string, args map[string]any) error {
	args["accountId"] = account
	body, err := json.Marshal(map[string]any{
		"using":       []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"},
		"methodCalls": []any{[]any{method, args, "a"}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/jmap/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	type failure struct {
		Type string `json:"type"`
	}
	var out struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	var res struct {
		Type         string             `json:"type"`
		NotCreated   map[string]failure `json:"notCreated"`
		NotUpdated   map[string]failure `json:"notUpdated"`
		NotDestroyed map[string]failure `json:"notDestroyed"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || len(out.MethodResponses) != 1 || len(out.MethodResponses[0]) != 3 ||
		json.Unmarshal(out.MethodResponses[0][1], &res) != nil {
		return fmt.Errorf("%s: unexpected response", method)
	}
	if res.Type != "" {
		return &stalwartapi.MethodError{Method: method, Type: res.Type}
	}
	for _, failed := range []map[string]failure{res.NotCreated, res.NotUpdated, res.NotDestroyed} {
		for _, f := range failed {
			return &stalwartapi.MethodError{Method: method, Type: f.Type}
		}
	}
	return nil
}

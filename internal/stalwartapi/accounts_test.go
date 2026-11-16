package stalwartapi

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func account(id, email string, permissions, roles map[string]any) map[string]any {
	name, _, _ := strings.Cut(email, "@")
	return map[string]any{"id": id, "@type": "User", "name": name, "domainId": "d1", "emailAddress": email, "permissions": permissions, "roles": roles}
}

var (
	inherit  = map[string]any{"@type": "Inherit"}
	userRole = map[string]any{"@type": "User"}
)

// accountsFake answers x:Account/query for exactly the local part "alice"
// and x:Account/get from accounts, listing unknown ids under notFound.
func accountsFake(t *testing.T, accounts map[string]map[string]any) *fakeStalwart {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:Account/query":
			filter, _ := args["filter"].(map[string]any)
			if len(filter) == 1 && filter["name"] == "alice" {
				return method, map[string]any{"ids": []string{"a1", "a2"}}
			}
			return method, map[string]any{"ids": []string{}}
		case "x:Domain/get":
			return method, map[string]any{"list": []any{
				map[string]any{"id": "d1", "name": "example.org"},
				map[string]any{"id": "d2", "name": "example.net"},
			}}
		case "x:Account/get":
			list, notFound := []any{}, []any{}
			ids, _ := args["ids"].([]any)
			for _, id := range ids {
				if a, ok := accounts[id.(string)]; ok {
					list = append(list, a)
				} else {
					notFound = append(notFound, id)
				}
			}
			return method, map[string]any{"list": list, "notFound": notFound}
		case "x:Account/set":
			return method, map[string]any{"updated": map[string]any{"a1": nil, "a2": nil}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	return f
}

func TestAccountByAddressPicksMatchingDomain(t *testing.T) {
	f := accountsFake(t, map[string]map[string]any{
		"a1": account("a1", "alice@example.org", inherit, userRole),
		"a2": account("a2", "alice@example.net", inherit, userRole),
	})
	c := f.keyClient()
	ctx := context.Background()

	got, found, err := c.AccountByAddress(ctx, "Alice@Example.NET")
	if err != nil || !found || got.ID != "a2" || got.Email != "alice@example.net" {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want a2", got, found, err)
	}
	if m := f.methods(); !reflect.DeepEqual(m, []string{"x:Account/query", "x:Account/get"}) {
		t.Fatalf("calls = %v; want one name query, no domain list and no walk over every account", m)
	}
	if s := asJSON(t, f.callAt(0).Args["filter"]); s != `{"name":"alice"}` {
		t.Fatalf("query filter = %s", s)
	}
	// U+0130 lowers to an ASCII i under Unicode rules; it must not reach alice.
	for _, address := range []string{"alice", "@example.org", "alice@example.com", "bob@example.org", "AL\u0130CE@example.org"} {
		got, found, err = c.AccountByAddress(ctx, address)
		if err != nil || found {
			t.Fatalf("AccountByAddress(%q) = %+v, %v, %v; want not found", address, got, found, err)
		}
	}

	all, err := c.AccountsNamed(ctx, "alice")
	if err != nil || len(all) != 2 || all[0].ID != "a1" || all[1].ID != "a2" {
		t.Fatalf("AccountsNamed = %+v, %v; want a1 and a2", all, err)
	}
	if none, err := c.AccountsNamed(ctx, "Alice"); err != nil || len(none) != 0 {
		t.Fatalf("AccountsNamed(Alice) = %+v, %v; the name match is exact", none, err)
	}
}

// directoryFake answers like a Stalwart with domains and accounts: a name
// query lists the accounts with that local part, a query without a filter
// pages through every id by limit and position, and get reads accounts with
// their aliases. extra ids pad the full listing ahead of the accounts.
func directoryFake(t *testing.T, domains []any, accounts []map[string]any, extra int) *fakeStalwart {
	f := newFake(t)
	var all []string
	for i := 0; i < extra; i++ {
		all = append(all, "pad"+strconv.Itoa(i))
	}
	byID := map[string]map[string]any{}
	for _, a := range accounts {
		all = append(all, a["id"].(string))
		byID[a["id"].(string)] = a
	}
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:Domain/get":
			return method, map[string]any{"list": domains}
		case "x:Account/query":
			if filter, ok := args["filter"].(map[string]any); ok {
				ids := []string{}
				for _, a := range accounts {
					if len(filter) == 1 && a["name"] == filter["name"] {
						ids = append(ids, a["id"].(string))
					}
				}
				return method, map[string]any{"ids": ids}
			}
			pos, limit := int(args["position"].(float64)), int(args["limit"].(float64))
			end := min(pos+limit, len(all))
			return method, map[string]any{"ids": all[min(pos, end):end]}
		case "x:Account/get":
			list := []any{}
			ids, _ := args["ids"].([]any)
			for _, id := range ids {
				if a, ok := byID[id.(string)]; ok {
					list = append(list, a)
				}
			}
			return method, map[string]any{"list": list, "notFound": []any{}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	return f
}

// directory has domain a (example.org, alias example.net), domain b
// (example.com) and domain c (example.info). Account bob@example.org has the
// alias robert in domain a and the alias rob in domain b.
func directory(t *testing.T, extra int) *fakeStalwart {
	domains := []any{
		map[string]any{"id": "a", "name": "example.org", "aliases": map[string]any{"example.net": true}},
		map[string]any{"id": "b", "name": "example.com", "aliases": map[string]any{}},
		map[string]any{"id": "c", "name": "example.info"},
	}
	bob := account("bob1", "bob@example.org", inherit, userRole)
	bob["domainId"] = "a"
	bob["aliases"] = map[string]any{
		"0": map[string]any{"name": "robert", "domainId": "a", "enable": true, "description": nil},
		"1": map[string]any{"name": "rob", "domainId": "b", "enable": false, "description": nil},
	}
	other := account("carol1", "carol@example.com", inherit, userRole)
	other["domainId"] = "b"
	return directoryFake(t, domains, []map[string]any{other, bob}, extra)
}

// walks counts queries that list every account.
func walks(f *fakeStalwart) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if _, filtered := c.Args["filter"]; c.Method == "x:Account/query" && !filtered {
			out = append(out, asJSON(f.t, map[string]any{"limit": c.Args["limit"], "position": c.Args["position"]}))
		}
	}
	return out
}

func TestAccountByAddressResolvesAlias(t *testing.T) {
	f := directory(t, 0)
	got, found, err := f.keyClient().AccountByAddress(context.Background(), "Robert@Example.org")
	if err != nil || !found || got.ID != "bob1" || got.Email != "bob@example.org" {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want bob1", got, found, err)
	}
	// A disabled alias still signs in nowhere today, but may be switched on.
	got, found, err = f.keyClient().AccountByAddress(context.Background(), "rob@example.com")
	if err != nil || !found || got.ID != "bob1" {
		t.Fatalf("disabled alias = %+v, %v, %v; want bob1", got, found, err)
	}
	// The primary address needs no walk over every account.
	before := len(walks(f))
	if got, found, err = f.keyClient().AccountByAddress(context.Background(), "bob@example.org"); err != nil || !found || got.ID != "bob1" {
		t.Fatalf("primary address = %+v, %v, %v; want bob1", got, found, err)
	}
	if n := len(walks(f)); n != before {
		t.Fatalf("a primary-address match walked every account (%d walks)", n-before)
	}
}

// A primary address is found by its local part alone, so a domain list that
// is too long to read whole cannot hide it.
func TestAccountByAddressPrimaryNeedsNoDomainList(t *testing.T) {
	f := directory(t, 0)
	inner := f.reply
	f.reply = func(method string, args map[string]any) (string, any) {
		if method == "x:Domain/get" {
			return "error", map[string]any{"type": "requestTooLarge"}
		}
		return inner(method, args)
	}
	got, found, err := f.keyClient().AccountByAddress(context.Background(), "Bob@Example.org")
	if err != nil || !found || got.ID != "bob1" {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want bob1", got, found, err)
	}
	if m := f.methods(); !reflect.DeepEqual(m, []string{"x:Account/query", "x:Account/get"}) {
		t.Fatalf("calls = %v; want the name query and its read only", m)
	}
}

func TestAccountByAddressResolvesDomainAlias(t *testing.T) {
	f := directory(t, 0)
	for _, address := range []string{"bob@example.net", "robert@example.net"} {
		got, found, err := f.keyClient().AccountByAddress(context.Background(), address)
		if err != nil || !found || got.ID != "bob1" {
			t.Fatalf("AccountByAddress(%q) = %+v, %v, %v; want bob1", address, got, found, err)
		}
	}
	if w := walks(f); len(w) != 1 {
		t.Fatalf("walks = %v; want one, for the alias on the alias domain only", w)
	}
}

func TestAccountByAddressAliasStaysInItsDomain(t *testing.T) {
	f := directory(t, 0)
	for _, address := range []string{"rob@example.info", "rob@example.org", "robert@example.com", "robert@example.info", "robert@unknown.example", "robert"} {
		got, found, err := f.keyClient().AccountByAddress(context.Background(), address)
		if err != nil || found {
			t.Fatalf("AccountByAddress(%q) = %+v, %v, %v; want not found", address, got, found, err)
		}
	}
}

func TestAccountByAddressAliasScanPages(t *testing.T) {
	f := directory(t, 600)
	got, found, err := f.keyClient().AccountByAddress(context.Background(), "robert@example.org")
	if err != nil || !found || got.ID != "bob1" {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want bob1", got, found, err)
	}
	want := []string{`{"limit":500,"position":0}`, `{"limit":500,"position":500}`}
	if w := walks(f); !reflect.DeepEqual(w, want) {
		t.Fatalf("walk requests = %v; want %v", w, want)
	}
	// A miss reads every page until an empty one.
	if _, found, err := f.keyClient().AccountByAddress(context.Background(), "nobody@example.org"); err != nil || found {
		t.Fatalf("miss: found %v, err %v", found, err)
	}
	want = append(want, `{"limit":500,"position":0}`, `{"limit":500,"position":500}`, `{"limit":500,"position":602}`)
	if w := walks(f); !reflect.DeepEqual(w, want) {
		t.Fatalf("walk requests = %v; want %v", w, want)
	}
}

// listAll changes the answer to a query without a filter.
func listAll(f *fakeStalwart, change func(ids []string) []string) {
	inner := f.reply
	f.reply = func(method string, args map[string]any) (string, any) {
		m, v := inner(method, args)
		if _, filtered := args["filter"]; method == "x:Account/query" && !filtered {
			res := v.(map[string]any)
			res["ids"] = change(res["ids"].([]string))
		}
		return m, v
	}
}

// A server may return fewer ids than asked for; a short page is not the end.
func TestAccountByAddressAliasScanCappedPages(t *testing.T) {
	f := directory(t, 600)
	listAll(f, func(ids []string) []string { return ids[:min(len(ids), 200)] })
	got, found, err := f.keyClient().AccountByAddress(context.Background(), "robert@example.org")
	if err != nil || !found || got.ID != "bob1" {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want bob1", got, found, err)
	}
	want := []string{`{"limit":500,"position":0}`, `{"limit":500,"position":200}`, `{"limit":500,"position":400}`, `{"limit":500,"position":600}`}
	if w := walks(f); !reflect.DeepEqual(w, want) {
		t.Fatalf("walk requests = %v; want %v", w, want)
	}
}

// A server that repeats a page must not keep the walk going forever.
func TestAccountByAddressAliasScanStopsOnRepeatedPage(t *testing.T) {
	f := directory(t, 10)
	listAll(f, func([]string) []string { return []string{"pad0", "pad1"} })
	if got, found, err := f.keyClient().AccountByAddress(context.Background(), "robert@example.org"); err == nil || found {
		t.Fatalf("AccountByAddress = %+v, %v, %v; want an error", got, found, err)
	}
	if w := walks(f); len(w) != 2 {
		t.Fatalf("walk requests = %v; want the walk to stop at the first repeated page", w)
	}
}

// A whole account carries its credentials, secrets included. Every read of
// the account reader names only the fields it decodes.
func TestAccountReadsNameTheirProperties(t *testing.T) {
	f := directory(t, 600)
	c := f.keyClient()
	ctx := context.Background()
	if _, found, err := c.AccountByAddress(ctx, "robert@example.org"); err != nil || !found {
		t.Fatalf("alias: found %v, err %v", found, err)
	}
	if _, found, err := c.AccountByAddress(ctx, "bob@example.org"); err != nil || !found {
		t.Fatalf("primary: found %v, err %v", found, err)
	}
	if _, found, err := c.Account(ctx, "bob1"); err != nil || !found {
		t.Fatalf("Account: found %v, err %v", found, err)
	}
	if err := c.EnableSignIn(ctx, "bob1"); err != nil {
		t.Fatalf("EnableSignIn: %v", err)
	}
	gets := 0
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if call.Method != "x:Account/get" {
			continue
		}
		gets++
		if s := asJSON(t, call.Args["properties"]); s != `["id","name","emailAddress","permissions","roles","aliases"]` {
			t.Fatalf("x:Account/get properties = %s", s)
		}
	}
	// Two walk pages, the primary lookup, Account and EnableSignIn's read.
	if gets != 5 {
		t.Fatalf("x:Account/get calls = %d, want 5", gets)
	}
}

func TestDomainsReadsAliases(t *testing.T) {
	got, err := directory(t, 0).keyClient().Domains(context.Background())
	want := []Domain{{ID: "a", Name: "example.org", Aliases: []string{"example.net"}}, {ID: "b", Name: "example.com"}, {ID: "c", Name: "example.info"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Domains = %+v, %v; want %+v", got, err, want)
	}
}

func TestAccountFlags(t *testing.T) {
	f := accountsFake(t, map[string]map[string]any{
		"admin":    account("admin", "admin@example.org", inherit, map[string]any{"@type": "Admin"}),
		"disabled": account("disabled", "alice@example.org", map[string]any{"@type": "Merge", "enabledPermissions": map[string]any{}, "disabledPermissions": map[string]any{"authenticate": true}}, userRole),
		"plain":    account("plain", "bob@example.org", map[string]any{"@type": "Replace", "enabledPermissions": map[string]any{}, "disabledPermissions": map[string]any{"authenticate": false}}, userRole),
		"custom":   account("custom", "carol@example.org", inherit, map[string]any{"@type": "Custom", "roleIds": map[string]any{"r1": true}}),
	})
	c := f.keyClient()
	for id, want := range map[string]Account{
		"admin":    {ID: "admin", Name: "admin", Email: "admin@example.org", Admin: true, Inherit: true},
		"disabled": {ID: "disabled", Name: "alice", Email: "alice@example.org", SignInDisabled: true},
		"plain":    {ID: "plain", Name: "bob", Email: "bob@example.org"},
		"custom":   {ID: "custom", Name: "carol", Email: "carol@example.org", Inherit: true},
	} {
		got, found, err := c.Account(context.Background(), id)
		if err != nil || !found || got != want {
			t.Fatalf("Account(%s) = %+v, %v, %v; want %+v", id, got, found, err, want)
		}
	}
	if _, found, err := c.Account(context.Background(), "gone"); err != nil || found {
		t.Fatalf("missing account: found %v, err %v", found, err)
	}
}

func TestDisableSignInPatchesOrReplaces(t *testing.T) {
	f := accountsFake(t, nil)
	c := f.keyClient()
	ctx := context.Background()

	if err := c.DisableSignIn(ctx, Account{ID: "a1", Inherit: true}); err != nil {
		t.Fatalf("inherit: %v", err)
	}
	if s := asJSON(t, f.last().Args["update"]); s != `{"a1":{"permissions":{"@type":"Merge","disabledPermissions":{"authenticate":true}}}}` {
		t.Fatalf("inherit update = %s", s)
	}
	if err := c.DisableSignIn(ctx, Account{ID: "a2"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := f.last()
	if got.Method != "x:Account/set" {
		t.Fatalf("method = %q", got.Method)
	}
	if s := asJSON(t, got.Args["update"]); s != `{"a2":{"permissions/disabledPermissions/authenticate":true}}` {
		t.Fatalf("merge update = %s", s)
	}
}

func TestEnableSignInRemovesOnlyItsEntry(t *testing.T) {
	f := accountsFake(t, map[string]map[string]any{
		"a1": account("a1", "alice@example.org", inherit, userRole),
		"a2": account("a2", "alice@example.net", map[string]any{"@type": "Merge", "enabledPermissions": map[string]any{}, "disabledPermissions": map[string]any{"authenticate": true, "imapAuthenticate": true}}, userRole),
		"a3": account("a3", "carol@example.org", map[string]any{"@type": "Merge", "enabledPermissions": map[string]any{}, "disabledPermissions": map[string]any{}}, userRole),
	})
	c := f.keyClient()
	ctx := context.Background()

	if err := c.EnableSignIn(ctx, "a2"); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if want := []string{"x:Account/get", "x:Account/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	if s := asJSON(t, f.last().Args["update"]); s != `{"a2":{"permissions/disabledPermissions/authenticate":null}}` {
		t.Fatalf("update = %s", s)
	}

	// Inherit, an empty Merge and a missing account have no denial to remove.
	for _, id := range []string{"a1", "a3", "gone"} {
		before := len(f.methods())
		if err := c.EnableSignIn(ctx, id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got := f.methods()[before:]; !reflect.DeepEqual(got, []string{"x:Account/get"}) {
			t.Fatalf("%s: calls = %q, want only the read", id, got)
		}
	}
}

func TestSetReportsForbiddenGrant(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"notUpdated": map[string]any{"a2": map[string]any{
			"type": "forbidden", "description": "You are not authorized to grant permissions: sysAccountUpdate"}}}
	}
	err := f.keyClient().DisableSignIn(context.Background(), Account{ID: "a2"})
	var me *MethodError
	if !errors.As(err, &me) || me.Type != "forbidden" || me.Method != "x:Account/set" {
		t.Fatalf("err = %#v, want a forbidden MethodError", err)
	}
}

func TestAccountsNamedBatchesGets(t *testing.T) {
	const serverGetLimit = 500
	f := newFake(t)
	ids := make([]string, serverGetLimit+1)
	for i := range ids {
		ids[i] = strconv.Itoa(i)
	}
	f.reply = func(method string, args map[string]any) (string, any) {
		if method == "x:Account/query" {
			return method, map[string]any{"ids": ids}
		}
		requested := args["ids"].([]any)
		if len(requested) > serverGetLimit {
			return "error", map[string]any{"type": "requestTooLarge"}
		}
		list := []any{}
		for _, id := range requested {
			list = append(list, account(id.(string), "alice@domain"+id.(string)+".example.org", inherit, userRole))
		}
		return method, map[string]any{"list": list}
	}
	got, err := f.keyClient().AccountsNamed(context.Background(), "alice")
	if err != nil || len(got) != len(ids) {
		t.Fatalf("got %d accounts, error %v", len(got), err)
	}
	for i, a := range got {
		if a.ID != ids[i] {
			t.Fatalf("account %d out of order", i)
		}
	}
	if !reflect.DeepEqual(f.methods(), []string{"x:Account/query", "x:Account/get", "x:Account/get"}) {
		t.Fatal("unexpected request order")
	}
}

func TestDisableSignInRefusesKeyOwner(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"updated": map[string]any{testAccount: nil}}
	}
	err := f.keyClient().DisableSignIn(context.Background(), Account{ID: testAccount, Inherit: true})
	if err == nil {
		t.Fatal("key disabled its own account")
	}
	if len(f.methods()) != 0 {
		t.Fatal("self-suspension sent a mutation")
	}
}

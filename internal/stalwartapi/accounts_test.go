package stalwartapi

import (
	"context"
	"errors"
	"reflect"
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

	for _, id := range []string{"a1", "gone"} {
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

package stalwartapi

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRoleByDescription(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:Role/query":
			if asJSON(t, args["filter"]) == `{"description":"CSM response"}` {
				return method, map[string]any{"ids": []string{"r9", "r1"}}
			}
			return method, map[string]any{"ids": []string{}}
		case "x:Role/get":
			return method, map[string]any{"list": []any{
				map[string]any{"id": "r9", "description": "CSM response old", "enabledPermissions": map[string]any{}, "roleIds": map[string]any{}},
				map[string]any{"id": "r1", "description": "CSM response",
					"enabledPermissions":  map[string]any{"sysAccountGet": true, "authenticate": true, "sysRoleGet": false},
					"disabledPermissions": map[string]any{"sysBlockedIpGet": true},
					"roleIds":             map[string]any{"u2": true, "u1": true}},
			}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	c := f.keyClient()
	ctx := context.Background()

	got, found, err := c.RoleByDescription(ctx, "CSM response")
	want := Role{ID: "r1", Description: "CSM response", Enabled: []string{"authenticate", "sysAccountGet"}, Disabled: []string{"sysBlockedIpGet"}, RoleIDs: []string{"u1", "u2"}}
	if err != nil || !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("RoleByDescription = %+v, %v, %v; want %+v", got, found, err, want)
	}
	if s := asJSON(t, f.callAt(1).Args["ids"]); s != `["r9","r1"]` {
		t.Fatalf("get ids = %s", s)
	}

	before := len(f.methods())
	got, found, err = c.RoleByDescription(ctx, "Other")
	if err != nil || found {
		t.Fatalf("missing role = %+v, %v, %v; want not found", got, found, err)
	}
	if calls := f.methods()[before:]; !reflect.DeepEqual(calls, []string{"x:Role/query"}) {
		t.Fatalf("calls = %q, want only the query", calls)
	}
}

func TestSaveRoleCreatesAndUpdates(t *testing.T) {
	created := map[string]any{"c": map[string]any{"id": "r7"}}
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		if _, ok := args["create"]; ok {
			return method, map[string]any{"created": created}
		}
		return method, map[string]any{"updated": map[string]any{"r1": nil}}
	}
	c := f.keyClient()
	ctx := context.Background()

	id, err := c.SaveRole(ctx, Role{Description: "CSM response", Enabled: []string{"sysAccountGet", "authenticate"}, RoleIDs: []string{"u1"}})
	if err != nil || id != "r7" {
		t.Fatalf("create = %q, %v; want r7", id, err)
	}
	got := f.last()
	if got.Method != "x:Role/set" || got.Args["update"] != nil {
		t.Fatalf("create call = %s %v", got.Method, got.Args)
	}
	if s := asJSON(t, got.Args["create"]); s != `{"c":{"description":"CSM response","disabledPermissions":{},"enabledPermissions":{"authenticate":true,"sysAccountGet":true},"roleIds":{"u1":true}}}` {
		t.Fatalf("create = %s", s)
	}

	id, err = c.SaveRole(ctx, Role{ID: "r1", Description: "CSM response", Enabled: []string{"authenticate"}})
	if err != nil || id != "r1" {
		t.Fatalf("update = %q, %v; want r1", id, err)
	}
	got = f.last()
	if got.Method != "x:Role/set" || got.Args["create"] != nil {
		t.Fatalf("update call = %s %v", got.Method, got.Args)
	}
	if s := asJSON(t, got.Args["update"]); s != `{"r1":{"disabledPermissions":{},"enabledPermissions":{"authenticate":true},"roleIds":{}}}` {
		t.Fatalf("update = %s", s)
	}

	created = map[string]any{"c": map[string]any{}}
	if id, err := c.SaveRole(ctx, Role{Description: "CSM response"}); err == nil {
		t.Fatalf("create without an id = %q, want an error", id)
	}
}

func TestDomains(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{
			map[string]any{"id": "d1", "name": "example.org"},
			map[string]any{"id": "d2", "name": "example.net"},
		}}
	}
	got, err := f.keyClient().Domains(context.Background())
	if want := []Domain{{ID: "d1", Name: "example.org"}, {ID: "d2", Name: "example.net"}}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Domains = %+v, %v; want %+v", got, err, want)
	}
	call := f.last()
	if ids, ok := call.Args["ids"]; call.Method != "x:Domain/get" || !ok || ids != nil {
		t.Fatalf("call = %s %v; want x:Domain/get with ids null", call.Method, call.Args)
	}
}

func TestCreateAccountHasNoCredentials(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"c": map[string]any{"id": "acc9"}}}
	}
	id, err := f.keyClient().CreateAccount(context.Background(), "csm", "d1", "r1")
	if err != nil || id != "acc9" {
		t.Fatalf("CreateAccount = %q, %v; want acc9", id, err)
	}
	got := f.last()
	if got.Method != "x:Account/set" {
		t.Fatalf("method = %q", got.Method)
	}
	s := asJSON(t, got.Args["create"])
	if strings.Contains(s, "credentials") {
		t.Fatalf("create sends credentials: %s", s)
	}
	if s != `{"c":{"@type":"User","domainId":"d1","name":"csm","roles":{"@type":"Custom","roleIds":{"r1":true}}}}` {
		t.Fatalf("create = %s", s)
	}
}

func TestAccountRole(t *testing.T) {
	f := accountsFake(t, map[string]map[string]any{
		"custom": account("custom", "csm@example.org", inherit, map[string]any{"@type": "Custom", "roleIds": map[string]any{"r2": true, "r1": true, "r3": false}}),
		"user":   account("user", "alice@example.org", inherit, userRole),
	})
	c := f.keyClient()
	ctx := context.Background()

	if got, err := c.AccountRoleIDs(ctx, "custom"); err != nil || !reflect.DeepEqual(got, []string{"r1", "r2"}) {
		t.Fatalf("custom roles = %q, %v; want r1 r2", got, err)
	}
	if got, err := c.AccountRoleIDs(ctx, "user"); err != nil || len(got) != 0 {
		t.Fatalf("built-in role = %q, %v; want none", got, err)
	}
	if got, err := c.AccountRoleIDs(ctx, "gone"); err == nil {
		t.Fatalf("missing account = %q, want an error", got)
	}

	if err := c.SetAccountRole(ctx, "a1", "r1"); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	got := f.last()
	if s := asJSON(t, got.Args["update"]); got.Method != "x:Account/set" || s != `{"a1":{"roles":{"@type":"Custom","roleIds":{"r1":true}}}}` {
		t.Fatalf("%s update = %s", got.Method, s)
	}
}

func TestAccountCredentialTypes(t *testing.T) {
	const pwSecret = "made-up-password-hash-must-not-leak"
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		var list []any
		switch ids, _ := args["ids"].([]any); {
		case len(ids) == 1 && ids[0] == "a1":
			list = []any{map[string]any{"id": "a1", "credentials": map[string]any{
				"0": map[string]any{"@type": "Password", "credentialId": "a", "expiresAt": nil, "allowedIps": map[string]any{}, "secret": pwSecret},
				"1": map[string]any{"@type": "ApiKey", "credentialId": "k1", "expiresAt": nil, "allowedIps": map[string]any{"127.0.0.1": true}, "secret": pwSecret},
			}}}
		case len(ids) == 1 && ids[0] == "a2":
			list = []any{map[string]any{"id": "a2", "credentials": map[string]any{}}}
		case len(ids) == 1 && ids[0] == "bad":
			list = []any{map[string]any{"id": "bad", "credentials": map[string]any{"0": map[string]any{"@type": 7, "secret": pwSecret}}}}
		}
		return method, map[string]any{"list": list, "notFound": []any{}}
	}
	c := f.keyClient()
	ctx := context.Background()

	got, err := c.AccountCredentialTypes(ctx, "a1")
	if err != nil || !reflect.DeepEqual(got, []string{"ApiKey", "Password"}) {
		t.Fatalf("password and key = %q, %v; want ApiKey Password", got, err)
	}
	if s := asJSON(t, f.last().Args["properties"]); f.last().Method != "x:Account/get" || s != `["id","credentials"]` {
		t.Fatalf("%s properties = %s", f.last().Method, s)
	}
	if got, err := c.AccountCredentialTypes(ctx, "a2"); err != nil || len(got) != 0 {
		t.Fatalf("no credentials = %q, %v; want none", got, err)
	}
	if got, err := c.AccountCredentialTypes(ctx, "gone"); err == nil {
		t.Fatalf("missing account = %q, want an error", got)
	}
	if _, err := c.AccountCredentialTypes(ctx, "bad"); err == nil || strings.Contains(err.Error(), pwSecret) {
		t.Fatalf("malformed credentials error = %v, want an error without the secret", err)
	}
}

func TestAccountRoleReadsOnlyRoleProperties(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		if asJSON(t, args["properties"]) != `["id","roles"]` {
			t.Error("role read requested unrelated account properties")
		}
		return method, map[string]any{"list": []any{map[string]any{"id": "a", "roles": customRoles("r")}}}
	}
	roles, err := f.keyClient().AccountRoleIDs(context.Background(), "a")
	if err != nil || !reflect.DeepEqual(roles, []string{"r"}) {
		t.Fatal("role read failed")
	}
}

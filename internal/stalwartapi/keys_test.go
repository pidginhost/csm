package stalwartapi

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const testNewSecret = "made-up-secret-must-not-leak"

func TestAPIKeyCallsUseOwnerAccount(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch {
		case method == "x:ApiKey/get":
			return method, map[string]any{"list": []any{
				map[string]any{"id": "k1", "description": "CSM", "allowedIps": map[string]any{"127.0.0.1": true}, "createdAt": "2026-11-15T10:00:00Z", "expiresAt": nil},
			}}
		case args["create"] != nil:
			return method, map[string]any{"created": map[string]any{"k": map[string]any{"id": "k2", "secret": testNewSecret}}}
		default:
			return method, map[string]any{"destroyed": []string{"k1"}}
		}
	}
	c := f.keyClient()
	ctx := context.Background()

	keys, err := c.APIKeys(ctx, "d")
	if want := []APIKey{{ID: "k1", Description: "CSM"}}; err != nil || !reflect.DeepEqual(keys, want) {
		t.Fatalf("APIKeys = %+v, %v; want %+v", keys, err, want)
	}
	if ids, ok := f.last().Args["ids"]; !ok || ids != nil {
		t.Fatalf("get ids = %v, want null to list every key", ids)
	}
	if _, _, err := c.CreateAPIKey(ctx, "d", "CSM", []string{"127.0.0.1"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := c.DeleteAPIKeys(ctx, "d", []string{"k1"}); err != nil {
		t.Fatalf("DeleteAPIKeys: %v", err)
	}
	if s := asJSON(t, f.last().Args["destroy"]); s != `["k1"]` {
		t.Fatalf("destroy = %s", s)
	}

	if want := []string{"x:ApiKey/get", "x:ApiKey/set", "x:ApiKey/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	for i := range 3 {
		if got := f.callAt(i).Args["accountId"]; got != "d" {
			t.Fatalf("%s accountId = %v, want the owner d", f.callAt(i).Method, got)
		}
	}
}

func TestCreateAPIKeyReturnsSecretOnce(t *testing.T) {
	var created map[string]any
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"k": created}}
	}
	c := f.keyClient()
	ctx := context.Background()

	created = map[string]any{"id": "k2", "secret": testNewSecret}
	id, secret, err := c.CreateAPIKey(ctx, "d", "CSM", []string{"127.0.0.1", "::1"})
	if err != nil || id != "k2" || secret != testNewSecret {
		t.Fatalf("CreateAPIKey = %q, secret match %v, %v; want k2 and the secret", id, secret == testNewSecret, err)
	}
	if s := asJSON(t, f.last().Args["create"]); s != `{"k":{"allowedIps":{"127.0.0.1":true,"::1":true},"description":"CSM"}}` {
		t.Fatalf("create = %s", s)
	}

	for name, reply := range map[string]map[string]any{
		"no secret": {"id": "k2-response-marker", "description": "CSM"},
		"no id":     {"secret": testNewSecret, "description": "CSM"},
	} {
		created = reply
		id, secret, err := c.CreateAPIKey(ctx, "d", "CSM", []string{"127.0.0.1"})
		if err == nil || id != "" || secret != "" {
			t.Fatalf("%s: id %q, secret set %v, err %v; want only an error", name, id, secret != "", err)
		}
		if msg := err.Error(); strings.Contains(msg, testNewSecret) || strings.Contains(msg, "k2-response-marker") {
			t.Fatalf("%s: error prints the response", name)
		}
	}
}

// An empty address list may mean a key that works from anywhere.
func TestCreateAPIKeyRefusesNoAllowedAddress(t *testing.T) {
	f := newFake(t)
	c := f.keyClient()
	for _, ips := range [][]string{nil, {}} {
		if _, _, err := c.CreateAPIKey(context.Background(), "d", "CSM", ips); err == nil {
			t.Fatalf("CreateAPIKey(%q) = nil error, want a refusal", ips)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("calls = %q, want none", f.methods())
	}
}

func TestCreateAPIKeyDoesNotEchoCreationFailure(t *testing.T) {
	for _, failureKind := range []string{"entry", "method", "name"} {
		f := newFake(t)
		f.reply = func(method string, _ map[string]any) (string, any) {
			failure := map[string]any{"type": "serverFail", "description": testNewSecret}
			if failureKind == "method" {
				return "error", failure
			}
			if failureKind == "name" {
				return testNewSecret, map[string]any{}
			}
			return method, map[string]any{"notCreated": map[string]any{"k": failure}}
		}
		_, _, err := f.client().CreateAPIKey(context.Background(), "owner", "CSM", []string{"127.0.0.1"})
		if err == nil {
			t.Fatal("creation failure reported success")
		}
		if strings.Contains(err.Error(), testNewSecret) {
			t.Fatal("creation error exposed the new secret")
		}
	}
}

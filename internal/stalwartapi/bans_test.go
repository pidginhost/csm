package stalwartapi

import (
	"context"
	"reflect"
	"testing"
)

func TestBlockedIPsExactAddress(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:BlockedIp/query":
			return method, map[string]any{"ids": []string{"b1", "b2"}}
		case "x:BlockedIp/get":
			if asJSON(t, args["ids"]) != `["b1","b2"]` {
				return "error", map[string]any{"type": "invalidArguments"}
			}
			return method, map[string]any{"list": []any{
				map[string]any{"id": "b1", "address": "203.0.113.9", "reason": "authFailure", "createdAt": "2026-11-15T10:00:00Z"},
				map[string]any{"id": "b2", "address": "203.0.113.9", "reason": "manual", "createdAt": "2026-11-15T10:00:00Z"},
			}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	got, err := f.keyClient().BlockedIPs(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatalf("BlockedIPs: %v", err)
	}
	if s := asJSON(t, f.callAt(0).Args["filter"]); f.callAt(0).Method != "x:BlockedIp/query" || s != `{"address":"203.0.113.9"}` {
		t.Fatalf("query %s filter = %s", f.callAt(0).Method, s)
	}
	want := []BlockedIP{{ID: "b1", Address: "203.0.113.9", Reason: "authFailure"}, {ID: "b2", Address: "203.0.113.9", Reason: "manual"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BlockedIPs = %+v, want %+v", got, want)
	}
}

func TestBlockedIPsNoneSkipsGet(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"ids": []string{}}
	}
	got, err := f.keyClient().BlockedIPs(context.Background(), "198.51.100.7")
	if err != nil || len(got) != 0 {
		t.Fatalf("BlockedIPs = %+v, %v; want none", got, err)
	}
	if want := []string{"x:BlockedIp/query"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
}

func TestDeleteBlockedIPsReloads(t *testing.T) {
	destroyed := []string{"b1", "b2"}
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		if method == "x:Action/set" {
			return method, map[string]any{"created": map[string]any{"r": map[string]any{}}}
		}
		return method, map[string]any{"destroyed": destroyed}
	}
	c := f.keyClient()
	ctx := context.Background()

	if err := c.DeleteBlockedIPs(ctx, []string{"b1", "b2"}); err != nil {
		t.Fatalf("DeleteBlockedIPs: %v", err)
	}
	if want := []string{"x:BlockedIp/set", "x:Action/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	if s := asJSON(t, f.callAt(0).Args["destroy"]); s != `["b1","b2"]` {
		t.Fatalf("destroy = %s", s)
	}
	if s := asJSON(t, f.callAt(1).Args["create"]); s != `{"r":{"@type":"ReloadBlockedIps"}}` {
		t.Fatalf("reload = %s", s)
	}

	destroyed = []string{"b1"}
	before := len(f.methods())
	if err := c.DeleteBlockedIPs(ctx, []string{"b1", "b2"}); err == nil {
		t.Fatal("an id missing from destroyed reported success")
	}
	if got := f.methods()[before:]; !reflect.DeepEqual(got, []string{"x:BlockedIp/set"}) {
		t.Fatalf("calls after a partial destroy = %q, want no reload", got)
	}

	before = len(f.methods())
	if err := c.DeleteBlockedIPs(ctx, nil); err != nil {
		t.Fatalf("no ids: %v", err)
	}
	if len(f.methods()) != before {
		t.Fatal("no ids still sent a request")
	}
}

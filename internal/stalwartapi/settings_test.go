package stalwartapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetTracingLevelCreatesAndUpdates(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		if _, ok := args["create"]; ok {
			return method, map[string]any{"created": map[string]any{"c": map[string]any{"id": "x9"}}}
		}
		return method, map[string]any{"updated": map[string]any{"x1": nil}}
	}
	c := f.client()

	if err := c.SetTracingLevel(ctx, "", "auth.failed", "info"); err != nil {
		t.Fatalf("create: %v", err)
	}
	got := f.last()
	if got.Method != "x:EventTracingLevel/set" {
		t.Fatalf("method = %q", got.Method)
	}
	if s := asJSON(t, got.Args["create"]); s != `{"c":{"event":"auth.failed","level":"info"}}` {
		t.Fatalf("create = %s", s)
	}

	if err := c.SetTracingLevel(ctx, "x1", "auth.failed", "info"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if s := asJSON(t, f.last().Args["update"]); s != `{"x1":{"level":"info"}}` {
		t.Fatalf("update = %s", s)
	}

	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"notCreated": map[string]any{"c": map[string]any{
			"type": "primaryKeyViolation", "description": "exists"}}}
	}
	err := c.SetTracingLevel(ctx, "", "auth.failed", "info")
	var me *MethodError
	if !errors.As(err, &me) || me.Type != "primaryKeyViolation" {
		t.Fatalf("err = %v, want primaryKeyViolation", err)
	}
}

func TestTracingLevelsLists(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		if _, ok := args["ids"]; !ok || args["ids"] != nil {
			t.Errorf("ids = %v, want null", args["ids"])
		}
		return method, map[string]any{"list": []any{map[string]any{"id": "a1", "event": "auth.failed", "level": "warn"}}}
	}
	got, err := f.client().TracingLevels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []TracingLevel{{ID: "a1", Event: "auth.failed", Level: "warn"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestBanPeriodsNullIsPermanent(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		if method == "x:Security/set" {
			return method, map[string]any{"updated": map[string]any{"singleton": nil}}
		}
		return method, map[string]any{"list": []any{map[string]any{
			"id": "singleton", "authBanPeriod": nil, "abuseBanPeriod": 3600000, "scanBanPeriod": nil, "loiterBanPeriod": 60000}}}
	}
	c := f.client()
	p, err := c.BanPeriods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Auth != nil || p.Scan != nil || p.Abuse == nil || *p.Abuse != time.Hour {
		t.Fatalf("periods = %+v", p)
	}
	if s := asJSON(t, f.last().Args["ids"]); s != `["singleton"]` {
		t.Fatalf("ids = %s", s)
	}

	if err := c.SetBanPeriods(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	got := f.last()
	if got.Method != "x:Security/set" {
		t.Fatalf("method = %q", got.Method)
	}
	if s := asJSON(t, got.Args["update"]); s != `{"singleton":{"abuseBanPeriod":86400000,"authBanPeriod":86400000,"scanBanPeriod":86400000}}` {
		t.Fatalf("update = %s", s)
	}
}

func TestHTTPSettingsReadsSingleton(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		if method == "x:Http/set" {
			return method, map[string]any{"updated": map[string]any{"singleton": nil}}
		}
		return method, map[string]any{"list": []any{map[string]any{"id": "singleton", "clientIpSource": "peer", "forwardedHops": 1}}}
	}
	c := f.client()
	h, err := c.HTTPSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h != (HTTPSettings{ClientIPSource: "peer", ForwardedHops: 1}) {
		t.Fatalf("settings = %+v", h)
	}
	got := f.last()
	if got.Method != "x:Http/get" || asJSON(t, got.Args["ids"]) != `["singleton"]` {
		t.Fatalf("call = %s %s", got.Method, asJSON(t, got.Args["ids"]))
	}

	if err := c.SetHTTPSettings(ctx, HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}); err != nil {
		t.Fatal(err)
	}
	if s := asJSON(t, f.last().Args["update"]); s != `{"singleton":{"clientIpSource":"xForwardedFor","forwardedHops":1}}` {
		t.Fatalf("update = %s", s)
	}
}

func TestHTTPSettingsMissingSingleton(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{}, "notFound": []any{"singleton"}}
	}
	if _, err := f.client().HTTPSettings(context.Background()); err == nil {
		t.Fatal("an empty singleton list was accepted")
	}
}

func TestSetFailureNotUpdated(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"notUpdated": map[string]any{"singleton": map[string]any{
			"type": "invalidProperties", "description": "bad hops"}}}
	}
	err := f.client().SetHTTPSettings(context.Background(), HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 99})
	var me *MethodError
	if !errors.As(err, &me) || me.Type != "invalidProperties" || me.Method != "x:Http/set" {
		t.Fatalf("err = %v", err)
	}
}

func TestListenersParsesBindAndProxyMaps(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{map[string]any{
			"id": "l1", "name": "http", "protocol": "http",
			"bind":                         map[string]any{"127.0.0.1:8080": true, "[::1]:8080": true},
			"overrideProxyTrustedNetworks": map[string]any{"192.0.2.0/24": true},
		}}}
	}
	got, err := f.client().Listeners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{{
		ID: "l1", Name: "http", Protocol: "http",
		Bind:          []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("[::1]:8080")},
		ProxyNetworks: []string{"192.0.2.0/24"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestListenersRejectsUnparsableBind(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{map[string]any{
			"id": "l1", "name": "http", "protocol": "http", "bind": map[string]any{"localhost:8080": true}}}}
	}
	if _, err := f.client().Listeners(context.Background()); err == nil {
		t.Fatal("an address CSM cannot read was accepted")
	}
}

func TestProxyTrustedNetworks(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"list": []any{map[string]any{
			"id": "singleton", "proxyTrustedNetworks": map[string]any{"198.51.100.0/24": true, "192.0.2.1/32": true}}}}
	}
	got, err := f.client().ProxyTrustedNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"192.0.2.1/32", "198.51.100.0/24"}) {
		t.Fatalf("got %v", got)
	}
	if c := f.last(); c.Method != "x:SystemSettings/get" || asJSON(t, c.Args["ids"]) != `["singleton"]` {
		t.Fatalf("call = %s", c.Method)
	}
}

func TestReloadSettingsSendsAction(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"r": map[string]any{
			"warnings": map[string]any{"b": "second", "a": map[string]any{"k": 1}}}}}
	}
	got, err := f.client().ReloadSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := f.last()
	if c.Method != "x:Action/set" || asJSON(t, c.Args["create"]) != `{"r":{"@type":"ReloadSettings"}}` {
		t.Fatalf("call = %s %s", c.Method, asJSON(t, c.Args["create"]))
	}
	if !reflect.DeepEqual(got, []string{`a: {"k":1}`, "b: second"}) {
		t.Fatalf("warnings = %q", got)
	}
}

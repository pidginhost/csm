package stalwartapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
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

func TestSpamSettings(t *testing.T) {
	for _, want := range []SpamSettings{
		{Enabled: true, ScoreSpam: 5},
		{Enabled: true, ScoreSpam: 5, ScoreReject: 12.5, ScoreDiscard: 18.25},
		{},
	} {
		f := newFake(t)
		f.reply = func(method string, _ map[string]any) (string, any) {
			return method, map[string]any{"list": []any{map[string]any{
				"id": "singleton", "enable": want.Enabled, "scoreSpam": want.ScoreSpam,
				"scoreReject": want.ScoreReject, "scoreDiscard": want.ScoreDiscard, "greylistFor": nil}}}
		}
		got, err := f.client().SpamSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("settings = %+v, want %+v", got, want)
		}
		if c := f.last(); c.Method != "x:SpamSettings/get" || asJSON(t, c.Args["ids"]) != `["singleton"]` {
			t.Fatalf("call = %s %s", c.Method, asJSON(t, c.Args["ids"]))
		}
	}
}

func TestSpamSettingsRejectsIncompleteSettings(t *testing.T) {
	for _, field := range []string{"enable", "scoreSpam", "scoreReject", "scoreDiscard"} {
		for _, missing := range []bool{false, true} {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				settings := map[string]any{"id": "singleton", "enable": true, "scoreSpam": 5, "scoreReject": 0, "scoreDiscard": 0}
				if missing {
					delete(settings, field)
				} else {
					settings[field] = nil
				}
				return method, map[string]any{"list": []any{settings}}
			}
			if _, err := f.client().SpamSettings(context.Background()); err == nil {
				t.Errorf("invalid %s accepted (missing=%v)", field, missing)
			}
		}
	}
}

func TestSpamFilterStageOff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter any
		want   bool
	}{
		{"default", map[string]any{"match": map[string]any{}, "else": "is_empty(authenticated_as)"}, false},
		{"off", map[string]any{"match": map[string]any{}, "else": "false"}, true},
		{"off with spaces", map[string]any{"match": map[string]any{}, "else": " false "}, true},
		{"rules before off", map[string]any{"match": map[string]any{"0": map[string]any{"if": "is_empty(authenticated_as)", "then": "true"}}, "else": "false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				return method, map[string]any{"list": []any{map[string]any{"id": "singleton", "enableSpamFilter": tc.filter}}}
			}
			got, err := f.client().SpamFilterStageOff(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("off = %v, want %v", got, tc.want)
			}
			if c := f.last(); c.Method != "x:MtaStageData/get" || asJSON(t, c.Args["ids"]) != `["singleton"]` {
				t.Fatalf("call = %s %s", c.Method, asJSON(t, c.Args["ids"]))
			}
		})
	}
}

func TestClassifySpam(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"c": map[string]any{
			"score": 11.2, "result": "ham", "tags": map[string]any{
				"RDNS_NONE":     map[string]any{"score": 1.0, "disposition": "score"},
				"DNSWL_BLOCKED": map[string]any{"score": 0.0, "disposition": "score"},
			}}}}
	}
	c := f.client()
	probe := SpamProbe{
		Message: "Subject: t\r\n\r\nhi\r\n", RemoteIP: "192.0.2.10", EhloDomain: "mx.example.com",
		MailFrom: "sender@example.com", RcptTo: "postmaster@example.com",
	}
	got, err := c.ClassifySpam(context.Background(), probe)
	if err != nil {
		t.Fatal(err)
	}
	call := f.last()
	want := `{"c":{"@type":"ClassifySpam","ehloDomain":"mx.example.com","isTls":false,"mailFrom":"sender@example.com","message":"Subject: t\r\n\r\nhi\r\n","rcptTo":{"postmaster@example.com":true},"remoteIp":"192.0.2.10"}}`
	if call.Method != "x:Action/set" || asJSON(t, call.Args["create"]) != want {
		t.Fatalf("call = %s %s", call.Method, asJSON(t, call.Args["create"]))
	}
	if !reflect.DeepEqual(got, SpamProbeResult{Score: 11.2, Result: "ham", Tags: []string{"DNSWL_BLOCKED", "RDNS_NONE"}}) {
		t.Fatalf("result = %+v", got)
	}

	// A tag's disposition is the rule's own action, not the verdict.
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"c": map[string]any{
			"score": 3.0, "result": "ham", "tags": map[string]any{
				"SOME_RULE": map[string]any{"score": 3.0, "disposition": "reject"},
			}}}}
	}
	got, err = c.ClassifySpam(context.Background(), probe)
	if err != nil {
		t.Fatal(err)
	}
	if got.Result != "ham" {
		t.Fatalf("result = %q, want ham", got.Result)
	}
}

func TestClassifySpamNotAcknowledged(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{}}
	}
	if _, err := f.client().ClassifySpam(context.Background(), BlocklistProbe); err == nil {
		t.Fatal("a probe without a created result was accepted")
	}
}

func TestSpamFilterStageOffRejectsUnexpectedShape(t *testing.T) {
	for _, filter := range []string{
		`null`, `{}`, `{"else":"false"}`, `{"match":null,"else":"false"}`,
		`{"match":[],"else":"false"}`, `{"match":[{"if":"true","then":"true"}],"else":"false"}`,
		`{"match":true,"else":"false"}`, `{"match":"false","else":"false"}`,
		`{"match":{}}`, `{"match":{},"else":null}`, `{"match":{},"else":false}`,
	} {
		t.Run(filter, func(t *testing.T) {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				return method, map[string]any{"list": []any{map[string]any{"id": "singleton", "enableSpamFilter": json.RawMessage(filter)}}}
			}
			off, err := f.client().SpamFilterStageOff(context.Background())
			if err == nil || off {
				t.Fatalf("unexpected shape: off = %v, err = %v", off, err)
			}
		})
	}
}

func TestClassifySpamRejectsIncompleteResult(t *testing.T) {
	for _, result := range []string{
		`null`, `{}`, `{"score":0,"tags":{}}`, `{"score":0,"result":"","tags":{}}`,
		`{"result":"ham","tags":{}}`, `{"score":null,"result":"ham","tags":{}}`,
		`{"score":0,"result":"ham"}`, `{"score":0,"result":"ham","tags":null}`,
	} {
		t.Run(result, func(t *testing.T) {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				return method, map[string]any{"created": map[string]any{"c": json.RawMessage(result)}}
			}
			if _, err := f.client().ClassifySpam(context.Background(), BlocklistProbe); err == nil {
				t.Fatal("incomplete classification accepted")
			}
		})
	}
}

func TestClassifySpamZeroScoreWithoutTags(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, _ map[string]any) (string, any) {
		return method, map[string]any{"created": map[string]any{"c": map[string]any{
			"score": 0, "result": "ham", "tags": map[string]any{},
		}}}
	}
	got, err := f.client().ClassifySpam(context.Background(), BlocklistProbe)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, SpamProbeResult{Score: 0, Result: "ham", Tags: []string{}}) {
		t.Fatalf("result = %+v", got)
	}
}

func TestSpamCallsRedactServerText(t *testing.T) {
	for _, operation := range []string{"settings", "stage", "classify", "classify failure", "classify output"} {
		t.Run(operation, func(t *testing.T) {
			f := newFake(t)
			f.reply = func(method string, _ map[string]any) (string, any) {
				switch operation {
				case "classify output":
					return method, map[string]any{"created": map[string]any{"c": map[string]any{
						"score": 0, "result": testPassword, "tags": map[string]any{testPassword: map[string]any{}},
					}}}
				case "classify failure":
					return method, map[string]any{"notCreated": map[string]any{"c": map[string]any{"type": "invalidProperties", "description": testPassword}}}
				default:
					return "error", map[string]any{"type": "serverFail", "description": testPassword}
				}
			}
			c := f.client()
			var err error
			switch operation {
			case "settings":
				_, err = c.SpamSettings(context.Background())
			case "stage":
				_, err = c.SpamFilterStageOff(context.Background())
			default:
				var got SpamProbeResult
				got, err = c.ClassifySpam(context.Background(), BlocklistProbe)
				if operation == "classify output" {
					if err != nil {
						t.Fatal("classification failed")
					}
					if got.Result != "[redacted]" || !reflect.DeepEqual(got.Tags, []string{"[redacted]"}) {
						t.Fatal("classification output was not redacted")
					}
					return
				}
			}
			if err == nil || strings.Contains(err.Error(), testPassword) || !strings.Contains(err.Error(), "[redacted]") {
				t.Fatal("server error was not returned and redacted")
			}
		})
	}
}

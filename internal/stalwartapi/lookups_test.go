package stalwartapi

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// lookupPages answers x:MemoryLookupKey/query with the pages in order, then
// empty pages, and x:MemoryLookupKey/get with one key per requested id.
func lookupPages(t *testing.T, pages ...[]string) *fakeStalwart {
	f := newFake(t)
	n := 0
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:MemoryLookupKey/query":
			ids := []string{}
			if n < len(pages) {
				ids = pages[n]
			}
			n++
			return method, map[string]any{"ids": ids}
		case "x:MemoryLookupKey/get":
			var list []any
			for _, id := range args["ids"].([]any) {
				list = append(list, map[string]any{"id": id, "key": "k-" + id.(string), "isGlobPattern": id.(string) == "i0"})
			}
			return method, map[string]any{"list": list}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	return f
}

func idRange(from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("i%d", i))
	}
	return out
}

func TestLookupKeysPagesUntilEmpty(t *testing.T) {
	f := lookupPages(t, idRange(0, 500), idRange(500, 620))
	got, err := f.keyClient().LookupKeys(context.Background(), "csm-ip-drop")
	if err != nil {
		t.Fatalf("LookupKeys: %v", err)
	}
	if len(got) != 620 {
		t.Fatalf("LookupKeys returned %d keys, want 620", len(got))
	}
	if got[0] != (LookupKey{ID: "i0", Key: "k-i0", Glob: true}) || got[619] != (LookupKey{ID: "i619", Key: "k-i619"}) {
		t.Fatalf("keys = %+v ... %+v", got[0], got[619])
	}
	var positions []string
	for i, m := range f.methods() {
		c := f.callAt(i)
		switch m {
		case "x:MemoryLookupKey/query":
			if s := asJSON(t, c.Args["filter"]); s != `{"namespace":"csm-ip-drop"}` {
				t.Fatalf("filter = %s", s)
			}
			positions = append(positions, asJSON(t, map[string]any{"limit": c.Args["limit"], "position": c.Args["position"]}))
		case "x:MemoryLookupKey/get":
			if n := len(c.Args["ids"].([]any)); n > 500 {
				t.Fatalf("get carried %d ids", n)
			}
			if s := asJSON(t, c.Args["properties"]); s != `["key","isGlobPattern"]` {
				t.Fatalf("properties = %s", s)
			}
		default:
			t.Fatalf("unexpected call %s", m)
		}
	}
	want := []string{`{"limit":500,"position":0}`, `{"limit":500,"position":500}`, `{"limit":500,"position":620}`}
	if !reflect.DeepEqual(positions, want) {
		t.Fatalf("pages = %q, want %q", positions, want)
	}
}

func TestLookupKeysRepeatedPageErrors(t *testing.T) {
	f := lookupPages(t, idRange(0, 3), idRange(0, 3), idRange(3, 6))
	if _, err := f.keyClient().LookupKeys(context.Background(), "csm-ip-drop"); err == nil {
		t.Fatal("a repeated page was accepted")
	}
	queries := 0
	for _, m := range f.methods() {
		if m == "x:MemoryLookupKey/query" {
			queries++
		}
	}
	if queries != 2 {
		t.Fatalf("queries = %d, want 2", queries)
	}
}

// A page that repeats part of the last one must not list an id twice: a
// duplicate would read as a duplicate key and get its only copy deleted.
func TestLookupKeysOverlappingPageKeepsUnique(t *testing.T) {
	f := lookupPages(t, idRange(0, 3), idRange(2, 5))
	got, err := f.keyClient().LookupKeys(context.Background(), "csm-ip-drop")
	if err != nil {
		t.Fatalf("LookupKeys: %v", err)
	}
	var ids []string
	for _, k := range got {
		ids = append(ids, k.ID)
	}
	if want := idRange(0, 5); !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %q, want %q", ids, want)
	}
}

// ackAll acknowledges every create and destroy of a set call.
func ackAll(method string, args map[string]any) (string, any) {
	res := map[string]any{}
	if create, ok := args["create"].(map[string]any); ok {
		created := map[string]any{}
		for id := range create {
			created[id] = map[string]any{"id": "s-" + id}
		}
		res["created"] = created
	}
	if update, ok := args["update"].(map[string]any); ok {
		updated := map[string]any{}
		for id := range update {
			updated[id] = nil
		}
		res["updated"] = updated
	}
	if destroy, ok := args["destroy"].([]any); ok {
		res["destroyed"] = destroy
	}
	return method, res
}

func TestCreateLookupKeysBatchesAndFlagsGlobs(t *testing.T) {
	keys := []string{"198.51.100.*"}
	for i := 0; i < 999; i++ {
		keys = append(keys, fmt.Sprintf("192.0.2.%d", i%256))
	}
	keys = append(keys, "203.0.113.9")
	f := newFake(t)
	f.reply = ackAll
	if err := f.keyClient().CreateLookupKeys(context.Background(), "csm-ip-drop", keys); err != nil {
		t.Fatalf("CreateLookupKeys: %v", err)
	}
	if want := []string{"x:MemoryLookupKey/set", "x:MemoryLookupKey/set", "x:MemoryLookupKey/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	sent, total := map[string]bool{}, 0
	for i, size := range []int{500, 500, 1} {
		create := f.callAt(i).Args["create"].(map[string]any)
		if len(create) != size {
			t.Fatalf("set %d created %d keys, want %d", i, len(create), size)
		}
		for _, v := range create {
			obj := v.(map[string]any)
			if obj["namespace"] != "csm-ip-drop" {
				t.Fatalf("create %s names no namespace", asJSON(t, obj))
			}
			sent[obj["key"].(string)] = obj["isGlobPattern"].(bool)
			total++
		}
	}
	if total != len(keys) {
		t.Fatalf("sent %d keys, want %d", total, len(keys))
	}
	if glob, ok := sent["198.51.100.*"]; !ok || !glob {
		t.Fatal("198.51.100.* was not sent as a glob")
	}
	if glob, ok := sent["203.0.113.9"]; !ok || glob {
		t.Fatal("203.0.113.9 was not sent as an exact key")
	}
}

func TestDeleteLookupKeysBatches(t *testing.T) {
	f := newFake(t)
	f.reply = ackAll
	if err := f.keyClient().DeleteLookupKeys(context.Background(), idRange(0, 501)); err != nil {
		t.Fatalf("DeleteLookupKeys: %v", err)
	}
	if want := []string{"x:MemoryLookupKey/set", "x:MemoryLookupKey/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	if a, b := len(f.callAt(0).Args["destroy"].([]any)), len(f.callAt(1).Args["destroy"].([]any)); a != 500 || b != 1 {
		t.Fatalf("destroys = %d, %d; want 500, 1", a, b)
	}
}

func TestReloadLookupStores(t *testing.T) {
	f := newFake(t)
	f.reply = ackAll
	if err := f.keyClient().ReloadLookupStores(context.Background()); err != nil {
		t.Fatalf("ReloadLookupStores: %v", err)
	}
	if want := []string{"x:Action/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	create := f.last().Args["create"].(map[string]any)
	if len(create) != 1 {
		t.Fatalf("create = %s", asJSON(t, create))
	}
	for _, v := range create {
		if s := asJSON(t, v); s != `{"@type":"ReloadLookupStores"}` {
			t.Fatalf("action = %s", s)
		}
	}
}

// ruleFake answers a rule query by name with the rule when it is given.
func ruleFake(t *testing.T, rule map[string]any) *fakeStalwart {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:SpamRule/query":
			if rule == nil || asJSON(t, args["filter"]) != `{"name":"CSM_IP"}` {
				return method, map[string]any{"ids": []string{}}
			}
			return method, map[string]any{"ids": []string{"r1"}}
		case "x:SpamRule/get":
			return method, map[string]any{"list": []any{rule}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	return f
}

func TestSpamRuleReadsArmsInOrder(t *testing.T) {
	ctx := context.Background()
	arm := func(n string) map[string]any { return map[string]any{"if": "if" + n, "then": "'S" + n + "'"} }
	rule := map[string]any{
		"@type": "Any", "id": "r1", "name": "CSM_IP", "enable": true, "priority": 500, "description": nil,
		"condition": map[string]any{"match": map[string]any{"10": arm("10"), "2": arm("2"), "0": arm("0")}, "else": "false"},
	}
	got, found, err := ruleFake(t, rule).keyClient().SpamRule(ctx, "CSM_IP")
	if err != nil || !found {
		t.Fatalf("SpamRule = %v, %v", found, err)
	}
	want := SpamRule{ID: "r1", Type: "Any", Enabled: true, Else: "false", Arms: []RuleArm{
		{If: "if0", Then: "'S0'"}, {If: "if2", Then: "'S2'"}, {If: "if10", Then: "'S10'"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SpamRule = %+v, want %+v", got, want)
	}

	if _, found, err := ruleFake(t, nil).keyClient().SpamRule(ctx, "CSM_IP"); found || err != nil {
		t.Fatalf("missing rule = %v, %v; want not found and no error", found, err)
	}

	rule["condition"] = map[string]any{"match": map[string]any{"0": arm("0"), "x": arm("x")}, "else": "false"}
	if _, _, err := ruleFake(t, rule).keyClient().SpamRule(ctx, "CSM_IP"); err == nil {
		t.Fatal("a non-numeric match key was accepted")
	}
}

func TestCreateSpamRuleShape(t *testing.T) {
	f := newFake(t)
	f.reply = ackAll
	arms := []RuleArm{{If: "key_exists('csm-ip-drop', remote_ip)", Then: "'CSM_IP_DROP'"}}
	err := f.keyClient().CreateSpamRule(context.Background(), "CSM_IP", SpamRule{Arms: arms, Else: "false"})
	if err != nil {
		t.Fatalf("CreateSpamRule: %v", err)
	}
	if want := []string{"x:SpamRule/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	create := f.last().Args["create"].(map[string]any)
	if len(create) != 1 {
		t.Fatalf("create = %s", asJSON(t, create))
	}
	want := `{"@type":"Any","condition":{"else":"false","match":{"0":{"if":"key_exists('csm-ip-drop', remote_ip)","then":"'CSM_IP_DROP'"}}},"enable":true,"name":"CSM_IP"}`
	for _, v := range create {
		if s := asJSON(t, v); s != want {
			t.Fatalf("rule = %s\nwant %s", s, want)
		}
	}
}

func TestSetSpamRuleCondition(t *testing.T) {
	f := newFake(t)
	f.reply = ackAll
	arms := []RuleArm{{If: "a", Then: "'A'"}, {If: "b", Then: "'B'"}}
	if err := f.keyClient().SetSpamRuleCondition(context.Background(), "r1", arms, "false"); err != nil {
		t.Fatalf("SetSpamRuleCondition: %v", err)
	}
	want := `{"r1":{"condition":{"else":"false","match":{"0":{"if":"a","then":"'A'"},"1":{"if":"b","then":"'B'"}}}}}`
	if c := f.last(); c.Method != "x:SpamRule/set" || asJSON(t, c.Args["update"]) != want {
		t.Fatalf("%s update = %s\nwant %s", c.Method, asJSON(t, c.Args["update"]), want)
	}
}

func TestSpamTagNotFound(t *testing.T) {
	f := newFake(t)
	f.reply = func(method string, args map[string]any) (string, any) {
		switch method {
		case "x:SpamTag/query":
			if asJSON(t, args["filter"]) == `{"tag":"CSM_IP_DROP"}` {
				return method, map[string]any{"ids": []string{"t1"}}
			}
			return method, map[string]any{"ids": []string{}}
		case "x:SpamTag/get":
			return method, map[string]any{"list": []any{map[string]any{"id": "t1", "@type": "Score", "tag": "CSM_IP_DROP", "score": 4.0}}}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	}
	c := f.keyClient()
	if _, found, err := c.SpamTag(context.Background(), "CSM_IP_CINS"); found || err != nil {
		t.Fatalf("missing tag = %v, %v; want not found and no error", found, err)
	}
	got, found, err := c.SpamTag(context.Background(), "CSM_IP_DROP")
	if want := (SpamTag{ID: "t1", Type: "Score", Tag: "CSM_IP_DROP", Score: 4}); err != nil || !found || got != want {
		t.Fatalf("SpamTag = %+v, %v, %v; want %+v", got, found, err, want)
	}
}

func TestCreateSpamTagShape(t *testing.T) {
	f := newFake(t)
	f.reply = ackAll
	if err := f.keyClient().CreateSpamTag(context.Background(), "CSM_IP_DROP", 4); err != nil {
		t.Fatalf("CreateSpamTag: %v", err)
	}
	if want := []string{"x:SpamTag/set"}; !reflect.DeepEqual(f.methods(), want) {
		t.Fatalf("calls = %q, want %q", f.methods(), want)
	}
	create := f.last().Args["create"].(map[string]any)
	if len(create) != 1 {
		t.Fatalf("create = %s", asJSON(t, create))
	}
	for _, v := range create {
		if s := asJSON(t, v); s != `{"@type":"Score","score":4,"tag":"CSM_IP_DROP"}` {
			t.Fatalf("tag = %s", s)
		}
	}
}

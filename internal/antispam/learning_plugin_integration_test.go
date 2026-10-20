//go:build integration

package antispam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Plugin tests run the embedded plugin under rspamd's own Lua with the
// fuzzy_check module, task and connection stubbed. Requires rspamadm on PATH:
// go test -tags integration ./internal/antispam

type pluginSent struct {
	Kind string         `json:"kind"`
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Body map[string]any `json:"body"`
}

type pluginCall struct {
	Rule    string `json:"rule"`
	Extra   int    `json:"extra"`
	Digests any    `json:"digests"`
}

type pluginRun struct {
	Sent  []pluginSent `json:"sent"`
	Calls []pluginCall `json:"calls"`
}

// list reads a UCL array, which encodes as {} when empty.
func list(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func digest(c byte) string { return strings.Repeat(string(c), 128) }

// runPlugin runs one scenario. hashes is a Lua table expression for
// hex_hashes' result, check a Lua function body run as check(cb, digests),
// params a Lua table expression for the request parameters.
func runPlugin(t *testing.T, hashes, check, params string, setup ...string) pluginRun {
	t.Helper()
	dir := t.TempDir()
	plugin := filepath.Join(dir, "csm_learning.lua")
	if err := os.WriteFile(plugin, []byte(LearningPlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "harness.lua")
	lua := fmt.Sprintf(`
local ucl = require 'ucl'
local timers, pending, sent, calls = {}, {}, {}, {}
local task = {}
function task:process_message() return true end
function task:add_timer(_, cb) timers[#timers + 1] = cb end
local function check_body(cb, digests)
%s
end
rspamd_plugins = rspamd_plugins or {}
rspamd_plugins.fuzzy_check = {
  hex_hashes = function(_, flag) assert(flag == 1); return %s end,
  check = function(_, cb, rule, timeout, digests, ...)
    calls[#calls + 1] = { rule = rule, extra = select('#', ...), digests = digests or false }
    return check_body(cb, digests)
  end,
}
local conn = {
  send_ucl = function(_, body)
    local parser = ucl.parser()
    assert(parser:parse_string(ucl.to_format(body, 'json-compact')))
    sent[#sent + 1] = { kind = 'ucl', body = parser:get_object() }
  end,
  send_error = function(_, code, msg) sent[#sent + 1] = { kind = 'error', code = code, msg = msg } end,
}
dofile(%q)
assert(rspamd_plugins.csm_learning.webui.inspect.need_task == true)
assert(rspamd_plugins.csm_learning.webui.inspect.enable == true)
%s
rspamd_plugins.csm_learning.webui.inspect.handler(task, conn, %s)
for _, cb in ipairs(pending) do cb() end
for _, cb in ipairs(timers) do cb() end
print(ucl.to_format({ sent = sent, calls = calls }, 'json-compact'))
`, check, hashes, plugin, strings.Join(setup, "\n"), params)
	if err := os.WriteFile(script, []byte(lua), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "rspamadm", "lua", "-b", script).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var run pluginRun
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &run); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	return run
}

func oneUCL(t *testing.T, run pluginRun) map[string]any {
	t.Helper()
	if len(run.Sent) != 1 || run.Sent[0].Kind != "ucl" {
		t.Fatalf("sent = %+v, want one reply", run.Sent)
	}
	return run.Sent[0].Body
}

func missReply(d string) string {
	return fmt.Sprintf("cb(true, nil, { queried = %q, type = 'text', found = false, prob = 0, value = 0, flag = 0 })", d)
}

func TestLearningPluginDeduplicatesDigests(t *testing.T) {
	d := digest('a')
	run := runPlugin(t, fmt.Sprintf("{ csm = { %q, %q } }", d, d), missReply(d)+"\nreturn true", "{}")
	body := oneUCL(t, run)
	if body["complete"] != true || body["distinct"] != float64(1) || len(list(body["results"])) != 1 {
		t.Fatalf("reply = %v", body)
	}
	r := list(body["results"])[0].(map[string]any)
	if r["queried"] != d || r["found"] != false || r["value"] != float64(0) {
		t.Fatalf("result = %v", r)
	}
	// A duplicate MIME part may be answered twice; equal replies agree.
	run = runPlugin(t, fmt.Sprintf("{ csm = { %q, %q } }", d, d), missReply(d)+"\n"+missReply(d)+"\nreturn true", "{}")
	if body := oneUCL(t, run); body["complete"] != true {
		t.Fatalf("echoed duplicate: %v", body)
	}
}

func TestLearningPluginRejectsBadDigests(t *testing.T) {
	var many []string
	for i := 0; i < 65; i++ {
		many = append(many, fmt.Sprintf("%0128x", i))
	}
	for name, param := range map[string]string{
		"short":     "abc",
		"upper":     strings.ToUpper(digest('a')),
		"empty":     "",
		"blank":     digest('a') + ",",
		"too many":  strings.Join(many, ","),
		"separator": digest('a') + ";" + digest('b'),
	} {
		t.Run(name, func(t *testing.T) {
			run := runPlugin(t, "{}", "error('check called')", fmt.Sprintf("{ digests = %q }", param))
			if len(run.Sent) != 1 || run.Sent[0].Kind != "error" || run.Sent[0].Code != 400 || len(run.Calls) != 0 {
				t.Fatalf("run = %+v", run)
			}
		})
	}
	// 64 distinct digests, repeated, are within the limit.
	param := strings.Join(append(many[:64], many[:64]...), ",")
	reply := "for _, d in ipairs(digests) do cb(true, nil, { queried = d, found = false, prob = 0, value = 0, flag = 0 }) end\nreturn true"
	run := runPlugin(t, "{}", reply, fmt.Sprintf("{ digests = %q }", param))
	body := oneUCL(t, run)
	if body["complete"] != true || body["distinct"] != float64(64) || len(list(run.Calls[0].Digests)) != 64 {
		t.Fatalf("64 digests: %v calls=%v", body, len(list(run.Calls[0].Digests)))
	}
}

func TestLearningPluginTooManyBodyDigests(t *testing.T) {
	var hashes []string
	for i := 0; i < 65; i++ {
		hashes = append(hashes, fmt.Sprintf("%q", fmt.Sprintf("%0128x", i)))
	}
	run := runPlugin(t, "{ csm = { "+strings.Join(hashes, ", ")+" } }", "error('check called')", "{}")
	body := oneUCL(t, run)
	if body["complete"] != false || len(run.Calls) != 0 || !strings.Contains(fmt.Sprint(body["errors"]), "too many digests") {
		t.Fatalf("reply = %v calls = %v", body, run.Calls)
	}
}

func TestLearningPluginReportsCheckError(t *testing.T) {
	d := digest('b')
	run := runPlugin(t, fmt.Sprintf("{ csm = { %q } }", d), "cb(false, nil, 'timeout waiting for the reply')\nreturn true", "{}")
	body := oneUCL(t, run)
	if body["complete"] != false || !strings.Contains(fmt.Sprint(body["errors"]), "timeout waiting for the reply") {
		t.Fatalf("reply = %v", body)
	}
	run = runPlugin(t, fmt.Sprintf("{ csm = { %q } }", d), "return false, 'no servers'", "{}")
	if body := oneUCL(t, run); body["complete"] != false || !strings.Contains(fmt.Sprint(body["errors"]), "no servers") {
		t.Fatalf("refused check: %v", body)
	}
	run = runPlugin(t, "error('hashing broke')", "error('check called')", "{}")
	if body := oneUCL(t, run); body["complete"] != false || len(run.Calls) != 0 {
		t.Fatalf("hashing failure: %v", body)
	}
}

func TestLearningPluginRejectsBadReplies(t *testing.T) {
	a, b, c := digest('a'), digest('b'), digest('c')
	hit := fmt.Sprintf("cb(true, nil, { queried = %q, found = true, digest = %q, prob = 1, value = 2, flag = 1, confirmed = true })", a, a)
	for name, tc := range map[string]struct{ hashes, check string }{
		// c was never queried.
		"unexpected": {fmt.Sprintf("{ csm = { %q, %q } }", a, b), missReply(c) + "\nreturn true"},
		// a was queried once and answered twice.
		"duplicate": {fmt.Sprintf("{ csm = { %q, %q } }", a, b), missReply(a) + "\n" + missReply(a) + "\nreturn true"},
		// a was queried twice and the answers disagree.
		"inconsistent": {fmt.Sprintf("{ csm = { %q, %q, %q } }", a, a, b), missReply(a) + "\n" + hit + "\nreturn true"},
	} {
		t.Run(name, func(t *testing.T) {
			body := oneUCL(t, runPlugin(t, tc.hashes, tc.check, "{}"))
			if body["complete"] != false {
				t.Fatalf("reply = %v", body)
			}
		})
	}
}

func TestLearningPluginTimerReplyOnce(t *testing.T) {
	d := digest('c')
	// The harness fires every timer after the handler returns.
	run := runPlugin(t, fmt.Sprintf("{ csm = { %q } }", d), missReply(d)+"\nreturn true", "{}")
	if body := oneUCL(t, run); body["complete"] != true {
		t.Fatalf("reply = %v", body)
	}
	run = runPlugin(t, fmt.Sprintf("{ csm = { %q } }", d), "return true", "{}")
	body := oneUCL(t, run)
	if body["complete"] != false || !strings.Contains(fmt.Sprint(body["errors"]), "timeout") {
		t.Fatalf("no reply: %v", body)
	}
}

func TestLearningPluginIgnoresRuleParameter(t *testing.T) {
	d := digest('d')
	run := runPlugin(t, fmt.Sprintf("{ csm = { %q }, other = { %q } }", d, digest('e')), missReply(d)+"\nreturn true", `{ rule = 'other', server = 'x', path = '/etc/passwd' }`)
	if len(run.Calls) != 1 || run.Calls[0].Rule != "csm" || run.Calls[0].Extra != 0 || run.Calls[0].Digests != false {
		t.Fatalf("calls = %+v", run.Calls)
	}
	if body := oneUCL(t, run); body["complete"] != true {
		t.Fatalf("reply = %v", body)
	}
}

func TestLearningPluginLoadsWithMarkerLine(t *testing.T) {
	if first, _, _ := strings.Cut(LearningPlugin, "\n"); first != "-- csm-managed-version: 1" {
		t.Fatalf("first line %q", first)
	}
	run := runPlugin(t, "{ csm = {} }", "error('check called')", "{}")
	body := oneUCL(t, run)
	if body["complete"] != true || body["distinct"] != float64(0) || len(run.Calls) != 0 {
		t.Fatalf("empty message: %v", body)
	}
}

func TestLearningPluginValidatesReplyContents(t *testing.T) {
	a, b := digest('a'), digest('b')
	for name, fields := range map[string]string{
		"missing found":       "prob = 0, value = 0, flag = 0",
		"wrong found type":    "found = 'false', prob = 0, value = 0, flag = 0",
		"missing miss value":  "found = false, prob = 0, flag = 0",
		"storage error":       "found = false, prob = 0, value = 503, flag = 0",
		"miss probability":    "found = false, prob = 0.25, value = 0, flag = 0",
		"missing hit digest":  "found = true, prob = 1, value = 2, flag = 1, confirmed = true",
		"short hit digest":    "found = true, digest = 'abc', prob = 1, value = 2, flag = 1, confirmed = true",
		"unconfirmed hit":     fmt.Sprintf("found = true, digest = %q, prob = 1, value = 2, flag = 1", a),
		"wrong flag":          fmt.Sprintf("found = true, digest = %q, prob = 1, value = 2, flag = 2, confirmed = true", a),
		"negative value":      fmt.Sprintf("found = true, digest = %q, prob = 1, value = -1, flag = 1, confirmed = true", a),
		"fractional value":    fmt.Sprintf("found = true, digest = %q, prob = 1, value = 1.5, flag = 1, confirmed = true", a),
		"missing probability": fmt.Sprintf("found = true, digest = %q, value = 2, flag = 1, confirmed = true", a),
		"large probability":   fmt.Sprintf("found = true, digest = %q, prob = 1.1, value = 2, flag = 1, confirmed = true", a),
		"nan probability":     fmt.Sprintf("found = true, digest = %q, prob = 0/0, value = 2, flag = 1, confirmed = true", a),
		"infinite value":      fmt.Sprintf("found = true, digest = %q, prob = 1, value = math.huge, flag = 1, confirmed = true", a),
	} {
		t.Run(name, func(t *testing.T) {
			check := fmt.Sprintf("cb(true, nil, { queried = %q, %s })\nreturn true", a, fields)
			body := oneUCL(t, runPlugin(t, fmt.Sprintf("{ csm = { %q } }", a), check, "{}"))
			if body["complete"] != false || len(list(body["errors"])) != 1 || len(list(body["results"])) != 0 {
				t.Fatalf("invalid reply accepted: %v", body)
			}
		})
	}
	for _, explicit := range []bool{false, true} {
		for _, stored := range []string{a, b} {
			params := "{}"
			if explicit {
				params = fmt.Sprintf("{ digests = %q }", a)
			}
			check := fmt.Sprintf("cb(true, nil, { queried = %q, found = true, digest = %q, prob = 0.9, value = 2, flag = 1, confirmed = true })\nreturn true", a, stored)
			body := oneUCL(t, runPlugin(t, fmt.Sprintf("{ csm = { %q } }", a), check, params))
			want := !explicit || stored == a
			if body["complete"] != want {
				t.Fatalf("explicit=%v exact=%v: %v", explicit, stored == a, body)
			}
			if want {
				results := list(body["results"])
				if len(results) != 1 || len(list(body["errors"])) != 0 {
					t.Fatalf("valid hit: %v", body)
				}
				r := results[0].(map[string]any)
				if r["queried"] != a || r["digest"] != stored || r["found"] != true || r["confirmed"] != true ||
					r["prob"] != 0.9 || r["value"] != float64(2) || r["flag"] != float64(1) {
					t.Fatalf("hit fields changed: %v", r)
				}
			} else if len(list(body["errors"])) != 1 || len(list(body["results"])) != 0 {
				t.Fatalf("exact check accepted near match: %v", body)
			}
		}
	}
}

func TestLearningPluginReportsProcessingFailure(t *testing.T) {
	for _, setup := range []string{
		"function task:process_message() return false end",
		"function task:process_message() return nil end",
		"function task:process_message() error('parse failed') end",
		"rspamd_plugins.fuzzy_check = nil",
	} {
		t.Run(setup, func(t *testing.T) {
			run := runPlugin(t, "{ csm = {} }", "error('check called')", "{}", setup)
			body := oneUCL(t, run)
			if body["complete"] != false || body["distinct"] != float64(0) || len(list(body["errors"])) != 1 || len(list(body["results"])) != 0 || len(run.Calls) != 0 {
				t.Fatalf("processing failure reported as empty message: %v", body)
			}
		})
	}
}

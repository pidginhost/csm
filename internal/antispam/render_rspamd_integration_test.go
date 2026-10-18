//go:build integration

package antispam

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Rspamd uses PCRE and decodes MIME headers before matching. RE2 alone cannot
// verify the rendered UCL or the input the scanner actually sees.
// Requires rspamadm on PATH: go test -tags integration ./internal/antispam
func TestRspamdInvisibleCJKSubject(t *testing.T) {
	files, err := RenderRspamd(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "regexp.conf")
	if err = os.WriteFile(rules, []byte(files["regexp.conf"]), 0o600); err != nil {
		t.Fatal(err)
	}
	type sample struct {
		Name, Message string
		Want          bool
	}
	var samples []sample
	for subject, want := range map[string]bool{
		"\u304a\u77e5\u3089\u200b\u305b":                   true,
		"\u200c\u91cd\u8981\u306a\u304a\u77e5\u3089\u305b": true,
		"\u4ee4\u548c\ufeff7":                              true,
		"\uc548\ub0b4\u2060\ub4dc\ub9bd\ub2c8\ub2e4":       true,
		"\u30ab\u30bf\u30ab\u30ca\u200d!":                  true,
		"\u304b\u3099\u200b!":                              true, // decomposed kana
		"\u6f22\U000e0100\u200b!":                          true, // Han variation selector
		"\uff76\u200b\uff80\uff76\uff85":                   true, // half-width kana
		"\u200b\uff70":                                     true, // half-width prolonged sound mark
		"\u30fc\u200b":                                     true, // prolonged sound mark
		"\u3400\u200b\u3401":                               true, // Han extension A
		"\U00020000\u200b\U00020001":                       true, // supplementary Han
		"\u1100\u200b\u1161":                               true, // decomposed Hangul
		"\u3131\u2060\u314f":                               true, // compatibility jamo
		"\u304a\u77e5\u3089\u305b\u3067\u3059":             false,
		"Retur\u200b produs":                               false,
		"\U0001f468\u200d\U0001f469 family":                false,
		"\u3010\u200b\u3011":                               false,
		"Notice\u30fb\u200bupdate":                         false, // middle dot
		"\u200b\u30a0":                                     false, // double hyphen
		"\u309b\u200b":                                     false, // spacing dakuten
		"\u200b\u3099":                                     false, // combining dakuten
		"\u2f00\u200b":                                     false, // Han radical symbol, not a letter
		"\u200b\u302e":                                     false, // Hangul tone mark
		"\u200b\u3040":                                     false, // unassigned code point
		"\ud7a4\u200b":                                     false, // beyond Hangul syllables
		"Weekly digest":                                    false,
		"":                                                 false,
	} {
		for name, header := range map[string]string{
			"raw":              subject,
			"base64":           mime.BEncoding.Encode("UTF-8", subject),
			"quoted-printable": mime.QEncoding.Encode("UTF-8", subject),
		} {
			samples = append(samples, sample{
				Name: fmt.Sprintf("%s/%+q", name, subject),
				Message: "From: sender@example.org\r\nTo: recipient@example.net\r\nSubject: " + header +
					"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nHello.\r\n",
				Want: want,
			})
		}
	}
	data, err := json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(cases, data, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "check.lua")
	lua := fmt.Sprintf(`
local ucl = require 'ucl'
local parser = ucl.parser()
assert(parser:parse_file(%q))
local rule = assert(parser:get_object().CSM_INVISIBLE_CJK_SUBJECT)
local pattern = assert(rule.re:match('^Subject=(/.*/u)$'))
local re = assert(require('rspamd_regexp').create(pattern))
assert(rule.score == 8.0)
parser = ucl.parser()
assert(parser:parse_file(%q))
local failures = 0
for _, sample in ipairs(parser:get_object()) do
  local ok, task = require('rspamd_task').load_from_string(sample.Message, rspamd_config)
  assert(ok)
  assert(task:process_message())
  local got = re:match(task:get_header('Subject') or '')
  if got ~= sample.Want then
    print(sample.Name .. ': got ' .. tostring(got) .. ', want ' .. tostring(sample.Want))
    failures = failures + 1
  end
  task:destroy()
end
assert(failures == 0, tostring(failures) .. ' incorrect subject verdicts')
`, rules, cases)
	if err := os.WriteFile(script, []byte(lua), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "rspamadm", "lua", "-b", script).CombinedOutput(); err != nil {
		t.Fatalf("rspamd subject checks: %v\n%s", err, out)
	}
}

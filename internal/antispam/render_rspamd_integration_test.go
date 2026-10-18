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
	for subject, want := range invisibleCJKSubjects {
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

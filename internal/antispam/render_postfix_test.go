package antispam

import (
	"net/netip"
	"strings"
	"testing"
)

// milter_headers.conf adds X-Spam-Status, which learning reads, and strips
// inbound copies so a sender cannot forge it. It leaves X-Spam alone: the
// proxy worker's own X-Spam: Yes is what the host's sieve files into Junk.
func TestRenderPostfixMilterHeaders(t *testing.T) {
	const want = "# csm-managed-version: 1\n" +
		"use = [\"x-spam-status\"];\n" +
		"remove = { \"X-Spam-Status\" = 0; };\n"
	for _, dry := range []bool{false, true} {
		files, err := RenderPostfix(defaults(dry))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 2 {
			t.Fatalf("dry run %t: files %v", dry, files)
		}
		if got := files[MilterHeadersPath]; got != want {
			t.Errorf("dry run %t: milter_headers.conf = %q, want %q", dry, got, want)
		}
		if !ManagedFor(TargetRspamdLua, files[PostfixScopeLuaPath]) {
			t.Errorf("dry run %t: scope Lua %q lacks CSM's marker", dry, files[PostfixScopeLuaPath])
		}
	}
	if _, err := RenderPostfix(Settings{}); err == nil {
		t.Error("invalid settings rendered")
	}
}

// The scope Lua carries CSM's thresholds in tenths, the mode, and the
// operator's exemptions and infra_ips networks in the order configured, each
// as a quoted Lua string. Nothing else in it varies.
func TestRenderPostfixScopeLua(t *testing.T) {
	s := defaults(false)
	s.Stack = StackPostfix
	s.Exempt = []string{"b@example.org", "example.com", "a@example.org"}
	s.ScopeNets = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("192.0.2.7/24")}
	files, err := RenderPostfix(s)
	if err != nil {
		t.Fatal(err)
	}
	lua := files[PostfixScopeLuaPath]
	if !ManagedFor(TargetRspamdLua, lua) {
		t.Fatalf("scope Lua lacks CSM's marker: %q", lua)
	}
	for _, want := range []string{
		"\nlocal MODE = \"enforce\"\n",
		"\nlocal REJECT, TAG = 150, 60\n",
		"\nlocal NETS = { \"198.51.100.0/24\", \"2001:db8:1::/48\", \"192.0.2.0/24\" }\n",
		"\nlocal EXEMPT = { \"b@example.org\", \"example.com\", \"a@example.org\" }\n",
		"name = 'CSM_SCOPE'",
		"name = 'CSM_MARKER'",
		"rspamd_logger.errx(rspamd_config, 'csm_scope: ",
		"rspamd_config:register_dependency('CSM_SCOPE', 'SETTINGS_APPLY')",
		"'CSM-ANTISPAM event=scan mode=%s policy=%s result=ok score=%d action=\"%s\" decision=%s ip=%s qid=%s'",
	} {
		if !strings.Contains(lua, want) {
			t.Errorf("scope Lua lacks %q:\n%s", want, lua)
		}
	}
	for _, placeholder := range []string{"$MODE", "$REJECT", "$TAG", "$NETS", "$EXEMPT"} {
		if strings.Contains(lua, placeholder) {
			t.Errorf("scope Lua keeps %s", placeholder)
		}
	}

	s.DryRun, s.RejectScore, s.TagScore, s.Exempt, s.ScopeNets = true, 30, 10, nil, nil
	if files, err = RenderPostfix(s); err != nil {
		t.Fatal(err)
	}
	lua = files[PostfixScopeLuaPath]
	for _, want := range []string{"\nlocal MODE = \"dry-run\"\n", "\nlocal REJECT, TAG = 300, 100\n", "\nlocal NETS = {  }\n", "\nlocal EXEMPT = {  }\n"} {
		if !strings.Contains(lua, want) {
			t.Errorf("dry run scope Lua lacks %q:\n%s", want, lua)
		}
	}
}

// Only validated values reach the Lua: a quote, space or wildcard in an
// exemption, or an invalid network, stops rendering.
func TestRenderPostfixRejectsUnsafeScope(t *testing.T) {
	for name, s := range map[string]Settings{
		"quote":    {Exempt: []string{`x"`}},
		"space":    {Exempt: []string{"a b@example.com"}},
		"wildcard": {Exempt: []string{"*@example.com"}},
		"network":  {ScopeNets: []netip.Prefix{{}}},
	} {
		d := defaults(false)
		d.Stack, d.Exempt, d.ScopeNets = StackPostfix, s.Exempt, s.ScopeNets
		if _, err := RenderPostfix(d); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

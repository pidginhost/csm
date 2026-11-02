package antispam

import (
	_ "embed"
	"strconv"
	"strings"
)

// milterHeaders makes rspamd's milter add X-Spam-Status, which learning
// reads to skip mail CSM tagged, and strip inbound copies so a sender
// cannot forge it. It also adds the host's Authentication-Results and strips
// inbound copies, which a sender could forge too. rspamd adds neither header
// to authenticated or local mail, so no login name reaches outbound mail.
// X-Spam stays: the proxy worker's own X-Spam: Yes is what the host's sieve
// rules file into Junk.
const milterHeaders = ManagedHeader + "\nuse = [\"x-spam-status\", \"authentication-results\"];\nremove = { \"X-Spam-Status\" = 0; };\n"

// postfixScope is the scope Lua with $ placeholders for validated values.
// Its file name is fixed: scan records are read from rspamd log lines that
// name it.
//
//go:embed postfix_scope.lua
var postfixScope string

// RenderPostfix returns the files CSM owns only on a Postfix host, keyed by
// path: the milter headers and the scope Lua.
func RenderPostfix(s Settings) (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return map[string]string{
		MilterHeadersPath:   milterHeaders,
		PostfixScopeLuaPath: renderScope(s),
	}, nil
}

// renderScope fills the scope Lua. Each operator string is validated ASCII
// and becomes a quoted Lua string; thresholds are in tenths.
func renderScope(s Settings) string {
	mode := "enforce"
	if s.DryRun {
		mode = "dry-run"
	}
	nets := make([]string, len(s.ScopeNets))
	for i, p := range s.ScopeNets {
		nets[i] = strconv.Quote(p.Masked().String())
	}
	exempt := make([]string, len(s.Exempt))
	for i, e := range s.Exempt {
		exempt[i] = strconv.Quote(e)
	}
	return strings.NewReplacer(
		"$MODE", strconv.Quote(mode),
		"$REJECT", strconv.Itoa(s.RejectScore*10),
		"$TAG", strconv.Itoa(s.TagScore*10),
		"$NETS", strings.Join(nets, ", "),
		"$EXEMPT", strings.Join(exempt, ", "),
	).Replace(postfixScope)
}

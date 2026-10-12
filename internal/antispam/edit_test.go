package antispam

import (
	"strings"
	"testing"
)

const operatorRule = "warn\n  log_message = operator rule\n"

func TestSetBlockHook(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	stale := renderedHooks(t, Settings{Socket: DefaultSocket, RejectScore: 20, TagScore: 6})
	for name, tc := range map[string]struct{ content, block, want string }{
		"empty file":          {"", h.Post, h.Post},
		"operator rule kept":  {operatorRule, h.Post, h.Post + operatorRule},
		"stale block updated": {stale.Post + operatorRule, h.Post, h.Post + operatorRule},
		"block moved first":   {operatorRule + stale.Post, h.Post, h.Post + operatorRule},
		"remove keeps rule":   {h.Post + operatorRule, "", operatorRule},
		"remove only block":   {h.Post, "", ""},
		"remove nothing":      {operatorRule, "", operatorRule},
		"no final newline":    {strings.TrimSuffix(h.Post, "\n"), h.Post, h.Post},
	} {
		got, err := SetBlock(TargetEximHook, tc.content, tc.block)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, tc.want)
		}
	}
}

func TestSetBlockHookRefuses(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	for name, content := range map[string]string{
		"two blocks":         h.Post + h.Post,
		"unpaired marker":    MarkerBegin + "\n" + operatorRule,
		"continues csm rule": "  message = joins the previous statement\n",
	} {
		if got, err := SetBlock(TargetEximHook, content, h.Post); err == nil {
			t.Errorf("%s: edited to %q", name, got)
		}
	}
}

func TestSetBlockLocal(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	moved := renderedHooks(t, Settings{Socket: "/run/rspamd/other.sock", RejectScore: 15, TagScore: 6})
	guard := "@ROUTERSTART@\n# CSM-FORWARD-GUARD ROUTER BEGIN (managed by csm; do not edit)\ncsm_forward_guard:\n  driver = accept\n# CSM-FORWARD-GUARD ROUTER END\n"
	for name, tc := range map[string]struct{ content, block, want string }{
		"skeleton":            {"@AUTH@\n\n@CONFIG@\n\n" + guard, h.Config, "@AUTH@\n\n@CONFIG@\n" + h.Config + "\n" + guard},
		"stale block updated": {"@CONFIG@\n" + moved.Config + "keep_environment =\n", h.Config, "@CONFIG@\n" + h.Config + "keep_environment =\n"},
		"block moved":         {"@CONFIG@\n" + guard + moved.Config, h.Config, "@CONFIG@\n" + h.Config + guard},
		"last line":           {"@AUTH@\n@CONFIG@", h.Config, "@AUTH@\n@CONFIG@\n" + h.Config},
		"remove":              {"@CONFIG@\n" + h.Config + guard, "", "@CONFIG@\n" + guard},
	} {
		got, err := SetBlock(TargetEximLocal, tc.content, tc.block)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, tc.want)
		}
	}
	if got, err := SetBlock(TargetEximLocal, "@AUTH@\n", h.Config); err == nil {
		t.Errorf("file without @CONFIG@ edited to %q", got)
	}
}

func TestSetBlockIsIdempotent(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	for _, tc := range []struct {
		kind           TargetKind
		content, block string
	}{
		{TargetEximHook, operatorRule, h.RCPT},
		{TargetEximLocal, "@AUTH@\n\n@CONFIG@\n\n@ROUTERSTART@\n", h.Config},
	} {
		once, err := SetBlock(tc.kind, tc.content, tc.block)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := SetBlock(tc.kind, once, tc.block)
		if err != nil || twice != once {
			t.Errorf("second edit changed %q to %q (%v)", once, twice, err)
		}
		if text, ok := BlockText(tc.kind, once); !ok || text != tc.block {
			t.Errorf("BlockText = %q, %t", text, ok)
		}
	}
}

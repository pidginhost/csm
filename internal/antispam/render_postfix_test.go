package antispam

import "testing"

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

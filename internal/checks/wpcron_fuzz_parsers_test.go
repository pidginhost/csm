package checks

import "testing"

func FuzzCpanelHandlerVersion(f *testing.F) {
	f.Add(cpanelHandlerBlock("ea-php73", "___lsphp"))
	f.Add(cpanelHandlerBlock("alt-php81", ""))
	f.Add(cpanelHandlerBegin + "\n# Inherit\n" + cpanelHandlerEnd)
	f.Add(cpanelHandlerBegin + "\nAddHandler custom-php .php\n" + cpanelHandlerEnd)
	f.Add("")
	f.Fuzz(func(t *testing.T, content string) {
		version, found := cpanelHandlerVersion(content)
		if version != "" && (!found || !safeManagedWPCronPHPBin(phpBinForVersion(version))) {
			t.Fatalf("handler emitted an unsafe selection (%q, %t)", version, found)
		}
		// Adding a complete block with no mapping cannot erase an earlier
		// .php mapping. Apache inherits mappings until a directive changes them.
		empty := cpanelHandlerBegin + "\n" + cpanelHandlerEnd + "\n"
		if v, ok := cpanelHandlerVersion(content + "\n" + empty); v != version || ok != found {
			t.Fatalf("empty block changed (%q, %t) to (%q, %t)", version, found, v, ok)
		}
	})
}

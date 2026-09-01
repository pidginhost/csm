package contenttype

import "testing"

func TestIsExecutablePHPExt(t *testing.T) {
	for _, ext := range []string{".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phtml", ".pht", ".PHP", ".PhTml"} {
		if !IsExecutablePHPExt(ext) {
			t.Errorf("IsExecutablePHPExt(%q) = false, want true", ext)
		}
	}
	for _, ext := range []string{".phps", ".html", ".txt", ".inc", "", "php", ".php.bak"} {
		if IsExecutablePHPExt(ext) {
			t.Errorf("IsExecutablePHPExt(%q) = true, want false", ext)
		}
	}
}

func TestIsExecutablePHPName(t *testing.T) {
	if !IsExecutablePHPName("wp-content/uploads/x.phtml") {
		t.Error("x.phtml must count as executable PHP")
	}
	if IsExecutablePHPName("source.phps") {
		t.Error(".phps renders as source and must not count as executable")
	}
	if !IsPHPSourceName("source.phps") {
		t.Error(".phps still holds PHP source and must receive content analysis")
	}
	if IsPHPSourceName("style.css") {
		t.Error("css is not PHP source")
	}
}

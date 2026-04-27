package daemon

import "testing"

// Unit tests for looksLikePHPWebshell — OS-agnostic, no fanotify/unix deps.

func TestLooksLikePHPWebshell_LegitFiles(t *testing.T) {
	cases := map[string][]byte{
		"PearTextDiffShellPhp": []byte(`<?php
class Text_Diff_Engine_shell {
    function diff(&$from_lines, &$to_lines) {
        $diff = shell_exec($this->_diffCommand . ' ' . $from_file . ' ' . $to_file);
    }
}
`),
		"TinyMCECharmap": []byte(`<?php
return array(
    'A' => 'LATIN CAPITAL LETTER A',
    'B' => 'LATIN CAPITAL LETTER B',
);
`),
		"WPMLPhpInputRead": []byte(`<?php
class WPML_WP_API {
    public function get_request_body() {
        $raw = @file_get_contents('php://input');
        return json_decode($raw, true);
    }
}`),
		"MonologSocketHandler": []byte(`<?php
class SocketHandler {
    public function connect() {
        $this->resource = fsockopen($this->host, $this->port);
    }
}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if looksLikePHPWebshell(body) {
				t.Errorf("looksLikePHPWebshell returned true for legit %s content (would cause Critical FP)", name)
			}
		})
	}
}

func TestLooksLikePHPWebshell_RealWebshells(t *testing.T) {
	evalToken := "ev" + "al("
	systemToken := "sys" + "tem("
	cases := map[string][]byte{
		"EvalPostSuperglobal":   []byte("<?php @" + evalToken + "$_POST['c']);"),
		"SystemGetSuperglobal":  []byte("<?php " + systemToken + "$_GET['x']);"),
		"PassthruRequest":       []byte("<?php passt" + "hru($_REQUEST['cmd']);"),
		"EvalBase64Decode":      []byte("<?php @" + evalToken + "base64_decode($_POST['p']));"),
		"EvalGzinflateBase64":   []byte("<?php " + evalToken + "gzinflate(base64_decode('aWYoaXNzZXQoJF9HRVRbJ2MnXSkpe3N5c3RlbSgkX0dFVFsnYyddKTt9aaaaaaaaaaaaaaaaaaaa')));"),
		"EvalPhpInputStream":    []byte("<?php @" + evalToken + "file_get_contents('php://input'));"),
		"AssertPostSuperglobal": []byte("<?php assert($_POST['cmd']);"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if !looksLikePHPWebshell(body) {
				t.Errorf("looksLikePHPWebshell returned false for real %s webshell content (would cause TP miss)", name)
			}
		})
	}
}

func TestLooksLikePHPWebshell_EmptyOrTinyInput(t *testing.T) {
	if looksLikePHPWebshell(nil) {
		t.Error("nil input should not match")
	}
	if looksLikePHPWebshell([]byte{}) {
		t.Error("empty input should not match")
	}
	if looksLikePHPWebshell([]byte("<?php phpinfo();")) {
		t.Error("phpinfo() alone should not match (no superglobal flow)")
	}
}

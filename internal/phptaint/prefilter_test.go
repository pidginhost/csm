package phptaint

import "testing"

func TestPrefilterAdmitsSourceAndSinkTogether(t *testing.T) {
	admit := []struct{ name, src string }{
		{"plain", "<?php $d = curl_exec($c); eval($d);"},
		{"mixed case", "<?php $d = CURL_EXEC($c); EVAL($d);"},
		{"short open tag", "<?= file_get_contents($u); ?> <?php include $x;"},
		{"comment between", "<?php /* c */ $d = file_get_contents($u); /* c */ require $d;"},
		{"whitespace", "<?php\n\n$d\t=\tfread($h, 1);\n\ninclude_once\t$d;"},
	}
	for _, c := range admit {
		if !isCandidate([]byte(c.src)) {
			t.Errorf("%s: isCandidate = false, want true", c.name)
		}
	}
}

func TestPrefilterRejectsWithoutBothHalves(t *testing.T) {
	reject := []struct{ name, src string }{
		{"no php tag", "curl_exec eval"},
		{"sink only", "<?php eval($x);"},
		{"source only", "<?php $d = curl_exec($c); echo $d;"},
		{"empty", ""},
	}
	for _, c := range reject {
		if isCandidate([]byte(c.src)) {
			t.Errorf("%s: isCandidate = true, want false", c.name)
		}
	}
}

package phptaint

import "testing"

// rejectFixture returns a 2 MiB source with a PHP open tag but no sink or
// source keyword: the common case when a daemon walks millions of real
// files and most of them have nothing worth flagging.
func rejectFixture() []byte {
	const size = 2 << 20 // matches MaxSourceBytes
	src := make([]byte, size)
	copy(src, "<?php\n")
	filler := []byte("the quick brown fox jumps over the lazy dog while a developer writes plain unremarkable code without any dangerous calls whatsoever ")
	for i := 6; i+len(filler) <= size; i += len(filler) {
		copy(src[i:], filler)
	}
	return src
}

func BenchmarkIsCandidateReject(b *testing.B) {
	src := rejectFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isCandidate(src)
	}
}

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

// TestPrefilterMatchesAcrossChunkBoundary guards the one subtle part of
// containsAnyFold's chunked folding: a keyword whose bytes straddle the
// boundary between two folded windows must still be found via the
// overlap, not silently missed because neither window held it whole.
func TestPrefilterMatchesAcrossChunkBoundary(t *testing.T) {
	needle := "curl_exec"
	pos := foldChunkBytes - 5 // 5 bytes land in the first window, the rest past it
	src := make([]byte, pos+len(needle)+2)
	for i := range src {
		src[i] = 'x'
	}
	copy(src, "<?php eval(")
	copy(src[pos:], needle)
	copy(src[pos+len(needle):], ");")
	if !isCandidate(src) {
		t.Fatal("isCandidate = false, want true: curl_exec straddles a fold-window boundary")
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

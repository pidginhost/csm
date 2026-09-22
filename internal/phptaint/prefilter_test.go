package phptaint

import (
	"context"
	"testing"
)

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
		IsCandidate(src)
	}
}

func TestMayBePHPSourceRequiresOnlyAnOpenTag(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{name: "full tag without flow keywords", src: "#!/usr/bin/php\n<?php echo 'ok';", want: true},
		{name: "echo tag", src: "HTML before <?= $value ?>", want: true},
		{name: "short tag", src: "<? echo 'ok'; ?>", want: true},
		{name: "flow keywords without tag", src: "curl_exec then eval", want: false},
		{name: "plain content", src: "PHP Warning: eval failed", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayBePHPSource([]byte(tc.src)); got != tc.want {
				t.Fatalf("MayBePHPSource() = %v, want %v", got, tc.want)
			}
		})
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
		if !IsCandidate([]byte(c.src)) {
			t.Errorf("%s: IsCandidate = false, want true", c.name)
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
	if !IsCandidate(src) {
		t.Fatal("IsCandidate = false, want true: curl_exec straddles a fold-window boundary")
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
		if IsCandidate([]byte(c.src)) {
			t.Errorf("%s: IsCandidate = true, want false", c.name)
		}
	}
}

// IsCandidate lets a caller that runs Analyze in another process skip the
// round trip for content the pre-filter rejects, so it must give exactly
// the answer Analyze gives by status.
func TestIsCandidateAgreesWithAnalyze(t *testing.T) {
	inputs := []string{
		"<?php $p = curl_exec($c); eval($p);",
		"<?php echo 'safe';",
		"<?php include $_GET['f'];",
		"<?PHP $b = FILE_GET_CONTENTS($u); ASSERT($b);",
		"body { color: red }",
		"\x89PNG\r\n\x1a\n<?php eval(fread($h, 9));",
		"eval(curl_exec($c)); // no open tag",
		"<?= wp_remote_retrieve_body($r); require $x;",
		"",
	}
	for _, in := range inputs {
		want := Analyze(context.Background(), []byte(in)).Status != StatusNotCandidate
		if got := IsCandidate([]byte(in)); got != want {
			t.Errorf("IsCandidate(%q) = %v, Analyze treats it as candidate = %v", in, got, want)
		}
	}
}

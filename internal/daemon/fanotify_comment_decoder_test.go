//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// realtimeChecksFor runs the realtime PHP content analysis over body and
// returns the check names it emitted.
func realtimeChecksFor(t *testing.T, body string) map[string]bool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.php")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)
	ch := make(chan alert.Finding, 16)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(fd, path, "pi")
	got := make(map[string]bool)
	for {
		select {
		case a := <-ch:
			got[a.Check] = true
		default:
			return got
		}
	}
}

func TestCheckPHPContent_DecoderExampleInDocblockStaysQuiet(t *testing.T) {
	// A stream filter library documents its deflate filter with a usage
	// example; the comment never runs.
	got := realtimeChecksFor(t, `<?php
namespace Clue\StreamFilter;

/**
 * Creates a filter function that compresses its input.
 *
 * $ret = fun('zlib.deflate')('helloworld');
 * assert('helloworld' === gzinflate($ret));
 */
function fun($filter, $parameters = null)
{
    return function ($chunk = null) use ($filter, $parameters) {
        return $chunk;
    };
}
`)
	if got["obfuscated_php_realtime"] {
		t.Error("obfuscated_php_realtime fired on a decoder example inside a docblock")
	}
}

func TestCheckPHPContent_DecoderInCodeStillFires(t *testing.T) {
	cases := map[string]string{
		"plain":                               "<?php\neval(gzinflate(base64_decode('S03OyFdIzs8rSc0rUVTy')));\n",
		"after tag-closed comment":            "<?php # build note ?><?php eval(gzinflate(base64_decode($p)));\n",
		"after a comment opener in page text": "<style>/* theme</style><?php eval(gzinflate(base64_decode($p))); ?>\n",
		"after a quote in page text":          "<p>don't hide PHP</p><?php eval(base64_decode($p)); ?>",
		"after slash comment close tag":       "<?php // note ?><?php eval(base64_decode($p));",
		"after CR line comment":               "<?php // note\reval(base64_decode($p));",
		"after close tag in string":           "<?php $s = '?>'; eval(base64_decode($p));",
		"after close tag in block comment":    "<?php /* ?> */ eval(base64_decode($p));",
		"after close tag in nowdoc":           "<?php $s = <<<'DOC'\n?>\nDOC;\neval(base64_decode($p));",
		"after CR nowdoc":                     "<?php $s = <<<'DOC'\r?>\rDOC;\reval(base64_decode($p));",
		"after close tag in shell string":     "<?php $s = `printf \\?>`; eval(base64_decode($p));",
		"after comment in shell string":       "<?php $s = `printf /*`; eval(base64_decode($p));",
		"after interpolated array key":        `<?php $s = "{$a["?>"]}"; eval(base64_decode($p));`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if !realtimeChecksFor(t, body)["obfuscated_php_realtime"] {
				t.Error("obfuscated_php_realtime missed eval wrapping a decoder in executable code")
			}
		})
	}
}

func TestCheckPHPContent_TailStartsInsideLiteral(t *testing.T) {
	body := "<?php $s = '" + strings.Repeat("x", 70000) + "'; eval(base64_decode($p));"
	if !realtimeChecksFor(t, body)["obfuscated_php_realtime"] {
		t.Error("tail window lost a decoder after a literal whose opener is outside the window")
	}
}

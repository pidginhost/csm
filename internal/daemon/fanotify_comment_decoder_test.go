//go:build linux

package daemon

import (
	"os"
	"path/filepath"
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
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if !realtimeChecksFor(t, body)["obfuscated_php_realtime"] {
				t.Error("obfuscated_php_realtime missed eval wrapping a decoder in executable code")
			}
		})
	}
}

package signatures

import (
	"reflect"
	"strings"
	"testing"
)

// A loader finding names the PHP file that was modified. Remediation needs
// the other half: the non-executable file that loader pulls in, which lives
// somewhere else entirely and survives a clean-up of the PHP alone.
func TestReferencedPayloadPathsNamesIncludedNonExecutableTargets(t *testing.T) {
	cases := map[string]struct {
		source string
		want   []string
	}{
		"variable_indirection": {
			source: `<?php if(isset($_COOKIE["sess_kx"])){$incName="/home/site/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png"; include($incName); exit;}`,
			want:   []string{"/home/site/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png"},
		},
		"literal_target": {
			source: "<?php if (!empty($_GET['p'])) { include_once \"assets/cache/data.dat\"; }",
			want:   []string{"assets/cache/data.dat"},
		},
		"minified_target": {
			source: "<?php include'payload.jpe';",
			want:   []string{"payload.jpe"},
		},
		"concatenated_target": {
			source: "<?php require dirname(__FILE__) . '/img/logo.gif';",
			want:   []string{"/img/logo.gif"},
		},
		"two_targets_deduplicated": {
			source: "<?php include 'a/one.png'; include 'a/one.png'; include 'b/two.zip';",
			want:   []string{"a/one.png", "b/two.zip"},
		},
		"source_partials_are_not_payloads": {
			source: "<?php include get_template_directory() . '/partials/hero.html'; require_once ABSPATH . 'wp-admin/includes/file.php'; include 'terms.txt';",
			want:   nil,
		},
		"asset_url_without_an_include": {
			source: "<?php $icon = plugin_dir_url(__FILE__) . 'assets/icon.png'; echo '<img src=\"' . $icon . '\">';",
			want:   nil,
		},
		"no_php_at_all": {
			source: "just some text mentioning include and logo.png",
			want:   nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := ReferencedPayloadPaths([]byte(tc.source))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ReferencedPayloadPaths = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReferencedPayloadPathsStopsAtOutputCap(t *testing.T) {
	body := []byte("<?php include 'a.png'; include 'b.png'; include 'c.png'; include 'd.png'; include 'e.png';" + strings.Repeat("include 'duplicate.png';", 20000))
	allocs := testing.AllocsPerRun(1, func() {
		if got := ReferencedPayloadPaths(body); !reflect.DeepEqual(got, []string{"a.png", "b.png", "c.png", "d.png", "e.png"}) {
			t.Fatalf("unexpected paths: %q", got)
		}
	})
	// Leave room for regexp pool churn under -race; a full input walk
	// allocates tens of thousands of match records for this fixture.
	if allocs > 1000 {
		t.Fatalf("extraction continued allocating after output cap: %.0f allocations", allocs)
	}
}

func BenchmarkReferencedPayloadPathsRepeated(b *testing.B) {
	body := []byte("<?php " + strings.Repeat("include 'same.png';", 20000))
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		ReferencedPayloadPaths(body)
	}
}

// Findings travel through alert channels, the audit log and webhooks. A file
// stuffed with thousands of include statements must not turn one finding into
// an unbounded payload.
func TestReferencedPayloadPathsIsBounded(t *testing.T) {
	source := "<?php "
	for i := 0; i < 50; i++ {
		source += "include 'assets/" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".png'; "
	}
	got := ReferencedPayloadPaths([]byte(source))
	if len(got) == 0 {
		t.Fatal("no payload paths extracted")
	}
	if len(got) > maxReferencedPayloadPaths {
		t.Errorf("returned %d paths, want at most %d", len(got), maxReferencedPayloadPaths)
	}
}

func TestReferencedPayloadDetailIsEmptyWithoutPayloadPaths(t *testing.T) {
	if got := ReferencedPayloadDetail([]byte("<?php include ABSPATH . 'wp-settings.php';")); got != "" {
		t.Errorf("ReferencedPayloadDetail = %q, want empty", got)
	}
}

func TestReferencedPayloadDetailListsPathsOnItsOwnLine(t *testing.T) {
	got := ReferencedPayloadDetail([]byte("<?php include 'a/one.png'; include 'b/two.zip';"))
	want := "\nIncluded payload files: a/one.png, b/two.zip"
	if got != want {
		t.Errorf("ReferencedPayloadDetail = %q, want %q", got, want)
	}
}

// The helper runs on every signature finding, whatever the file type. A
// JavaScript bundle calling its own include helper on an asset is not a PHP
// loader and must not be described as one.
func TestReferencedPayloadPathsIgnoresNonPHPContent(t *testing.T) {
	js := []byte(`define(["require"],function(require){require("./assets/sprite.png");include("./assets/logo.gif");});`)
	if got := ReferencedPayloadPaths(js); got != nil {
		t.Errorf("ReferencedPayloadPaths = %q, want nil", got)
	}
}

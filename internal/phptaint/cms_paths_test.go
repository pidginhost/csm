package phptaint

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/cms"
)

// cmsPathFixtureInventory is the checked-in expectation for every
// (CMS, constant) pair. It is deliberately not generated from cms.All():
// removing a constant from the descriptor table must fail here, not
// silently shrink the fixture set.
var cmsPathFixtureInventory = map[cms.Kind][]string{
	cms.WordPress: {"abspath"},
	cms.Joomla: {"jpath_root", "jpath_base", "jpath_site", "jpath_administrator", "jpath_api",
		"jpath_cache", "jpath_cli", "jpath_component", "jpath_component_administrator",
		"jpath_component_site", "jpath_configuration", "jpath_installation",
		"jpath_libraries", "jpath_manifests", "jpath_plugins", "jpath_public", "jpath_themes"},
	cms.Drupal: {"drupal_root"},
	cms.OpenCart: {"dir_application", "dir_cache", "dir_catalog", "dir_config", "dir_download",
		"dir_extension", "dir_image", "dir_language", "dir_logs", "dir_modification",
		"dir_opencart", "dir_root", "dir_session", "dir_storage", "dir_system",
		"dir_template", "dir_upload"},
	cms.Magento: {"bp"},
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestCMSPathFixtureInventoryMatchesDescriptors(t *testing.T) {
	descriptors := map[cms.Kind][]string{}
	for _, d := range cms.All() {
		descriptors[d.Kind] = sortedCopy(d.PathConstants)
	}
	for kind, want := range cmsPathFixtureInventory {
		got, ok := descriptors[kind]
		if !ok {
			t.Errorf("%s: fixtures exist but no descriptor", kind)
			continue
		}
		if strings.Join(got, ",") != strings.Join(sortedCopy(want), ",") {
			t.Errorf("%s: descriptor constants %v differ from fixture inventory %v", kind, got, want)
		}
		delete(descriptors, kind)
	}
	for kind := range descriptors {
		t.Errorf("%s: descriptor exists without fixture coverage", kind)
	}
}

// readShapes are the benign read-then-include forms every constant is
// exercised through: both dual-use read functions, each with the bare
// constant and with a literal suffix. The snippets are parsed as data only.
func readShapes(constant string) map[string]string {
	c := strings.ToUpper(constant)
	return map[string]string{
		"file_get_contents/bare":   fmt.Sprintf("<?php $p = file_get_contents(%s); include $p;", c),
		"file_get_contents/suffix": fmt.Sprintf("<?php $p = file_get_contents(%s . '/fixture.php'); include $p;", c),
		"fopen/bare":               fmt.Sprintf("<?php $h = fopen(%s, 'r'); $p = stream_get_contents($h); include $p;", c),
		"fopen/suffix":             fmt.Sprintf("<?php $h = fopen(%s . '/fixture.php', 'r'); $p = stream_get_contents($h); include $p;", c),
	}
}

func TestCMSPathConstantsAreLocalReads(t *testing.T) {
	for kind, consts := range cmsPathFixtureInventory {
		for _, c := range consts {
			for shape, src := range readShapes(c) {
				t.Run(fmt.Sprintf("%s/%s/%s", kind, c, shape), func(t *testing.T) {
					if _, isSource := sourceConfidence(firstCall(t, src)); isSource {
						t.Fatalf("%s treated as a remote source", strings.ToUpper(c))
					}
					rep := Analyze(context.Background(), []byte(src))
					if rep.Status != StatusAnalyzed {
						t.Fatalf("status %v (%s)", rep.Status, rep.Reason)
					}
					if len(rep.Results) != 0 || rep.TotalResults != 0 {
						t.Fatalf("unexpected flow: %+v", rep.Results)
					}
				})
			}
		}
	}
}

// The derivation must not have widened locality to every constant: an
// unknown constant in the same shapes still seeds reduced-confidence taint
// that reaches the include sink.
func TestUnknownConstantStillSeedsTaint(t *testing.T) {
	for shape, src := range readShapes("foo_root") {
		t.Run(shape, func(t *testing.T) {
			call := firstCall(t, src)
			conf, isSource := sourceConfidence(call)
			if !isSource || conf != ConfidenceLow {
				t.Fatalf("FOO_ROOT read: source=%v confidence=%v, want source at ConfidenceLow", isSource, conf)
			}
			rep := Analyze(context.Background(), []byte(src))
			if rep.Status != StatusAnalyzed || len(rep.Results) != 1 {
				t.Fatalf("report %+v", rep)
			}
			// The acquiring call is proven above through sourceConfidence; a
			// flow carried by a variable reports that variable as its source,
			// the same convention the other analyzer tests rely on.
			r := rep.Results[0]
			if r.Source != "$p" || r.Sink != "include" || r.Confidence != ConfidenceLow {
				t.Fatalf("result %+v, want source $p sink include at ConfidenceLow", r)
			}
		})
	}
}

// buildLocalPathConstants must read the descriptors it is given: a
// synthetic descriptor's constant appears in the built set, which the old
// literal table could never satisfy.
func TestBuildLocalPathConstantsReadsDescriptors(t *testing.T) {
	set := buildLocalPathConstants([]cms.Descriptor{{Kind: "synthetic", DBContentCheck: "db_content_synthetic", PathConstants: []string{"synth_root", "synth_cache"}}})
	if len(set) != 2 || !set["synth_root"] || !set["synth_cache"] {
		t.Fatalf("built set %v", set)
	}
	if set["abspath"] {
		t.Fatal("builder leaked constants from the production table")
	}
	prod := buildLocalPathConstants(cms.All())
	for kind, consts := range cmsPathFixtureInventory {
		for _, c := range consts {
			if !prod[c] {
				t.Errorf("%s: %s missing from the production set", kind, c)
			}
		}
	}
}

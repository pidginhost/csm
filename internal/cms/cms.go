// Package cms is the single declaration of the content management systems
// CSM supports. The taint analyzer, the database adapters and the clean
// corpus manifest are each tested against this table, so a CMS added to one
// of them without being declared here fails the build.
package cms

import (
	"fmt"
	"strings"
)

// Kind identifies a supported CMS. Values are the canonical lowercase names
// used in the corpus manifest and in check owner names.
type Kind string

const (
	WordPress Kind = "wordpress"
	Joomla    Kind = "joomla"
	Drupal    Kind = "drupal"
	OpenCart  Kind = "opencart"
	Magento   Kind = "magento"
)

// Descriptor records what the rest of the tree needs to know about a CMS.
type Descriptor struct {
	Kind Kind
	// DBContentCheck is the runner owner name of the adapter that scans this
	// CMS's database ("db_content" for WordPress, "db_content_joomla", ...).
	DBContentCheck string
	// PathConstants are the lower-cased PHP constants the CMS defines at
	// bootstrap that always hold a local filesystem path. They preserve the
	// analyzer's provenance assumptions; they are not proof of a constant's
	// runtime value.
	PathConstants []string
}

var descriptors = []Descriptor{
	{Kind: WordPress, DBContentCheck: "db_content", PathConstants: []string{"abspath"}},
	{Kind: Joomla, DBContentCheck: "db_content_joomla", PathConstants: []string{
		"jpath_root", "jpath_base", "jpath_site", "jpath_administrator", "jpath_api",
		"jpath_cache", "jpath_cli", "jpath_component", "jpath_component_administrator",
		"jpath_component_site", "jpath_configuration", "jpath_installation",
		"jpath_libraries", "jpath_manifests", "jpath_plugins", "jpath_public", "jpath_themes",
	}},
	{Kind: Drupal, DBContentCheck: "db_content_drupal", PathConstants: []string{"drupal_root"}},
	{Kind: OpenCart, DBContentCheck: "db_content_opencart", PathConstants: []string{
		"dir_application", "dir_cache", "dir_catalog", "dir_config", "dir_download",
		"dir_extension", "dir_image", "dir_language", "dir_logs", "dir_modification",
		"dir_opencart", "dir_root", "dir_session", "dir_storage", "dir_system",
		"dir_template", "dir_upload",
	}},
	{Kind: Magento, DBContentCheck: "db_content_magento", PathConstants: []string{"bp"}},
}

func (d Descriptor) clone() Descriptor {
	out := d
	out.PathConstants = append([]string(nil), d.PathConstants...)
	return out
}

// All returns every supported CMS in declaration order. The result is a
// deep copy; mutating it does not change policy.
func All() []Descriptor {
	out := make([]Descriptor, 0, len(descriptors))
	for _, d := range descriptors {
		out = append(out, d.clone())
	}
	return out
}

// Lookup returns the descriptor for k, or the zero descriptor and false.
func Lookup(k Kind) (Descriptor, bool) {
	for _, d := range descriptors {
		if d.Kind == k {
			return d.clone(), true
		}
	}
	return Descriptor{}, false
}

// Parse accepts only an exact declared kind. It does not trim or fold case,
// so a manifest or config value must be spelled canonically.
func Parse(s string) (Kind, bool) {
	for _, d := range descriptors {
		if string(d.Kind) == s {
			return d.Kind, true
		}
	}
	return "", false
}

// validateDescriptors reports the first shape violation in ds: kinds and
// owner names must be non-empty and unique, and path constants non-empty,
// lower case and unique within and across descriptors.
func validateDescriptors(ds []Descriptor) error {
	seenKind := make(map[Kind]bool, len(ds))
	seenOwner := make(map[string]bool, len(ds))
	seenConst := make(map[string]Kind)
	for _, d := range ds {
		if d.Kind == "" {
			return fmt.Errorf("descriptor with empty kind")
		}
		if seenKind[d.Kind] {
			return fmt.Errorf("%s: kind declared twice", d.Kind)
		}
		seenKind[d.Kind] = true
		if d.DBContentCheck == "" {
			return fmt.Errorf("%s: empty DBContentCheck", d.Kind)
		}
		if seenOwner[d.DBContentCheck] {
			return fmt.Errorf("%s: DBContentCheck %q reused", d.Kind, d.DBContentCheck)
		}
		seenOwner[d.DBContentCheck] = true
		if len(d.PathConstants) == 0 {
			return fmt.Errorf("%s: no path constants; local provenance cannot be analysed", d.Kind)
		}
		for _, c := range d.PathConstants {
			if c == "" || c != strings.ToLower(c) {
				return fmt.Errorf("%s: constant %q must be non-empty lower case", d.Kind, c)
			}
			if owner, dup := seenConst[c]; dup {
				return fmt.Errorf("constant %q declared by both %s and %s", c, owner, d.Kind)
			}
			seenConst[c] = d.Kind
		}
	}
	return nil
}

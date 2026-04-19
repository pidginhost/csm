package config

import (
	"reflect"
	"sync/atomic"
)

// Hot-reload policy (ROADMAP item 7).
//
// Each top-level field of Config carries an optional `hotreload`
// struct tag:
//
//   - "safe":    a SIGHUP reload swaps the field in place; readers
//     on the next tick see the new value.
//   - "restart": the field cannot be applied without a full daemon
//     restart (fanotify watched roots, bbolt path, web UI
//     listener). A SIGHUP that touches a restart field
//     logs a warning and leaves the prior config live.
//   - (none):    treated as restart-required. Tagging every safe
//     field explicitly is the strict default; this closes
//     the door on accidental hot-swaps of a fresh field
//     someone adds without considering the safety of live
//     mutation.
const (
	TagSafe    = "safe"
	TagRestart = "restart"
)

// active holds the current live config. Readers on hot paths (check
// tick handlers, alert dispatchers, metrics-auth) call Active() to
// pick up the latest snapshot after a SIGHUP. Writers (daemon
// startup, SIGHUP reload) call SetActive.
var active atomic.Pointer[Config]

// Active returns the current live Config pointer. Returns nil if
// SetActive has not been called; callers on hot paths are expected
// to nil-check once per call. Daemon startup calls SetActive before
// any tick runs, so a nil return in production is a bug.
func Active() *Config {
	return active.Load()
}

// SetActive installs cfg as the current live config.
func SetActive(cfg *Config) {
	active.Store(cfg)
}

// Change describes a single top-level field that differs between an
// old and a new Config.
type Change struct {
	// Field is the YAML name (from the `yaml:"..."` struct tag), or
	// the Go field name if no yaml tag is set.
	Field string
	// Tag is the hotreload classification: TagSafe, TagRestart, or
	// "" for fields with no explicit tag (treated as TagRestart).
	Tag string
}

// Diff reports which Config fields differ between old and new,
// classified by hotreload tag.
//
// The walk is recursive: if a top-level field is tagged, its tag
// applies to any change inside. If a nested field has its own tag,
// that tag wins over the parent (field-level overrides let a single
// safe field sit inside an otherwise restart-required parent, which
// is how webui.metrics_token can hot-reload even though the rest of
// WebUI needs a restart).
//
// Each Change carries the YAML path from root (e.g. "thresholds" for
// the top-level struct, "webui.metrics_token" for a nested leaf).
// The tag is the nearest tagged ancestor on that path; if nothing on
// the path is tagged, the Change's Tag is "" and the caller should
// treat that as TagRestart.
//
// Granularity rule: if a tagged ancestor classifies the whole
// subtree uniformly (parent tag applies, no nested overrides on
// changed leaves), the Change is reported at the parent level. That
// keeps the common case ("I changed three thresholds") as one
// "thresholds" Change. When a subtree contains a differently-tagged
// leaf, that leaf is reported separately with its own tag, and the
// parent (minus that leaf) is reported with the inherited tag.
func Diff(oldCfg, newCfg *Config) []Change {
	if oldCfg == nil || newCfg == nil {
		return nil
	}

	oldV := reflect.ValueOf(*oldCfg)
	newV := reflect.ValueOf(*newCfg)
	return diffStruct(oldV, newV, "", "")
}

// diffStruct walks two reflect.Values of the same struct type and
// returns Changes for every differing field. parentPath is the
// already-composed YAML dotted path down to this struct (empty at
// the root). parentTag is the effective hotreload tag inherited
// from the nearest tagged ancestor.
func diffStruct(oldV, newV reflect.Value, parentPath, parentTag string) []Change {
	var changes []Change
	t := oldV.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		// ConfigFile / Integrity are daemon-managed. See Diff's docstring.
		if parentPath == "" && (field.Name == "ConfigFile" || field.Name == "Integrity") {
			continue
		}

		oldField := oldV.Field(i).Interface()
		newField := newV.Field(i).Interface()
		if reflect.DeepEqual(oldField, newField) {
			continue
		}

		// Effective tag for this field: its own explicit tag wins;
		// otherwise inherit from the parent path.
		tag := field.Tag.Get("hotreload")
		if tag != TagSafe && tag != TagRestart {
			tag = parentTag
		}

		name := yamlFieldName(field)
		path := name
		if parentPath != "" {
			path = parentPath + "." + name
		}

		// If the field is itself a struct (not a pointer, slice,
		// map), recurse so nested overrides can surface separately.
		// Pointer-to-struct is treated as a leaf because the
		// reflect.DeepEqual already told us the pointer target
		// changed; re-walking it would produce duplicate noise.
		if field.Type.Kind() == reflect.Struct {
			nested := diffStruct(oldV.Field(i), newV.Field(i), path, tag)
			// If every nested Change carries the same tag and there
			// is no mixed classification, collapse to a single
			// Change at this level. Operators rarely need the
			// granularity "I changed thresholds.mail_queue_warn";
			// the collapse keeps the common case clean.
			if collapsed, ok := collapseIfUniform(nested, path, tag); ok {
				changes = append(changes, collapsed)
			} else {
				changes = append(changes, nested...)
			}
			continue
		}
		changes = append(changes, Change{Field: path, Tag: tag})
	}
	return changes
}

// collapseIfUniform returns (Change{Field:path, Tag:parentTag}, true)
// when every nested change inherits parentTag (i.e. nothing nested
// overrode it). Returns (_, false) when the subtree contains a
// differently-tagged leaf, which means the caller must keep the
// granular changes.
func collapseIfUniform(nested []Change, path, parentTag string) (Change, bool) {
	if len(nested) == 0 {
		return Change{}, false
	}
	for _, c := range nested {
		if c.Tag != parentTag {
			return Change{}, false
		}
	}
	return Change{Field: path, Tag: parentTag}, true
}

// RestartRequired returns true if any change in the diff carries a
// TagRestart classification (or no tag, which collapses to restart).
func RestartRequired(changes []Change) bool {
	for _, c := range changes {
		if c.Tag != TagSafe {
			return true
		}
	}
	return false
}

// yamlFieldName returns the yaml tag's primary name if set, else the
// Go field name. Strips any `,omitempty` / `,inline` suffix.
func yamlFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" || tag == "-" {
		return f.Name
	}
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i]
		}
	}
	return tag
}

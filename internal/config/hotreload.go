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

// Diff reports which top-level Config fields differ between old and
// new, classified by hotreload tag.
//
// Nested struct changes bubble up to the parent field: the parent is
// reported once with its own tag. Treating an entire top-level
// struct as a single unit keeps the SIGHUP decision logic simple and
// matches the granularity operators naturally think in ("I changed
// thresholds" / "I changed the webui listener").
//
// Fields with no `hotreload` tag are reported with Tag="" and the
// caller should treat that as TagRestart.
func Diff(oldCfg, newCfg *Config) []Change {
	if oldCfg == nil || newCfg == nil {
		return nil
	}
	var changes []Change

	oldV := reflect.ValueOf(*oldCfg)
	newV := reflect.ValueOf(*newCfg)
	t := oldV.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		// ConfigFile is the in-memory path of the loaded file. It
		// is not serialised and has no semantic meaning for reload.
		//
		// Integrity is daemon-managed: every successful reload
		// re-signs integrity.config_hash on the fresh file, so the
		// hash always differs from the prior config's stored value.
		// Treating that as a real diff would reject every reload.
		if field.Name == "ConfigFile" || field.Name == "Integrity" {
			continue
		}

		oldField := oldV.Field(i).Interface()
		newField := newV.Field(i).Interface()
		if reflect.DeepEqual(oldField, newField) {
			continue
		}

		tag := field.Tag.Get("hotreload")
		name := yamlFieldName(field)
		changes = append(changes, Change{Field: name, Tag: tag})
	}
	return changes
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

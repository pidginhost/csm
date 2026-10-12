package antispam

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
)

// RecordPath is CSM's completion record. Its directory is root-only 0700.
const RecordPath = "/var/lib/csm/antispam/installed.json"

// RecordFormat is the format of installed.json (spec section 6.3 step 6).
const RecordFormat = 1

// MaxRecordBytes bounds a completion record read from disk.
const MaxRecordBytes = 4 << 10

// Record is CSM's completion record. A nil Generation means an apply or
// remove started and did not finish, so reconcile must repeat it.
type Record struct {
	Format     int     `json:"format"`
	Generation *string `json:"generation"`
}

// Complete reports whether the record names an installed generation.
func (r Record) Complete() bool { return r.Generation != nil }

// EncodeRecord renders a record. An empty generation marks work in progress.
func EncodeRecord(generation string) []byte {
	r := Record{Format: RecordFormat}
	if generation != "" {
		r.Generation = &generation
	}
	data, _ := json.Marshal(r)
	return append(data, '\n')
}

var recordKeys = map[string]bool{"format": true, "generation": true}

// DecodeRecord reads installed.json strictly: exactly format 1 and a
// generation that is null or a SHA-256 hex digest.
func DecodeRecord(data []byte) (Record, error) {
	if len(data) > MaxRecordBytes {
		return Record{}, errors.New("installed record is too large")
	}
	fields, err := objectFields(data, recordKeys, "installed record")
	if err != nil {
		return Record{}, err
	}
	if len(fields) != len(recordKeys) {
		return Record{}, errors.New("installed record needs format and generation")
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, errors.New("installed record has a value of the wrong type")
	}
	if r.Format != RecordFormat {
		return Record{}, errors.New("installed record has an unsupported format")
	}
	if r.Generation != nil && !isDigest(*r.Generation) {
		return Record{}, errors.New("installed record has an invalid generation")
	}
	return r, nil
}

func isDigest(s string) bool {
	return len(s) == 2*sha256.Size && strings.Trim(s, "0123456789abcdef") == ""
}

// Generation identifies managed content: the SHA-256 of canonical JSON that
// maps each managed destination to its text, keys sorted, no HTML escaping.
func Generation(content map[string]string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(content) // a map of strings always encodes
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// ManagedContent maps each file CSM writes to the text it owns there: a
// whole local.d file, or the CSM block of a shared Exim file.
func ManagedContent(s Settings) (map[string]string, error) {
	hooks, err := RenderExim(s)
	if err != nil {
		return nil, err
	}
	files, err := RenderRspamd(s)
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		HookRCPTPath:      hooks.RCPT,
		HookScanPath:      hooks.Scan,
		HookPostPath:      hooks.Post,
		LocalEximConfPath: hooks.Config,
	}
	for name, text := range files {
		out[path.Join(RspamdLocalDir, name)] = text
	}
	return out, nil
}

// InstalledContent maps each target to the CSM text found in it, in the
// form ManagedContent uses. Unreadable, inactive or misplaced blocks are
// absent, so they cannot match a completed installation.
func InstalledContent(targets []TargetFacts) map[string]string {
	out := make(map[string]string)
	for _, t := range targets {
		if t.Err != nil || t.Missing {
			continue
		}
		if t.Kind == TargetRspamd {
			if IsManaged(t.Content) {
				out[t.Path] = t.Content
			}
		} else if text, ok := installedBlockText(t.Kind, t.Content); ok {
			out[t.Path] = text
		}
	}
	return out
}

func installedBlockText(kind TargetKind, content string) (string, bool) {
	section, acl := "", ""
	if kind == TargetEximHook {
		section, acl = "acl", "csm_hook"
	}
	// Ownership markers alone cannot prove that Exim runs the rendered text.
	blocks, err := locateBlocks(content, section, acl, true)
	if err != nil || len(blocks) != 1 {
		return "", false
	}
	b := blocks[0]
	lines := strings.SplitAfter(content, "\n")
	if kind == TargetEximHook {
		if b.Begin != 1 {
			return "", false
		}
	} else if !oneConfigSection(content) || b.Begin < 2 || lines[b.Begin-2] != "@CONFIG@\n" {
		return "", false
	}
	return strings.Join(lines[b.Begin-1:b.End], ""), true
}

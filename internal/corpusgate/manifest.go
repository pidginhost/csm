package corpusgate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/cms"
)

// ManifestVersion is the only accepted manifest version. Version 2 made the
// per-source cms field mandatory and added the pending list.
const ManifestVersion = 2

// PendingCMS records a supported CMS with no pinned clean source yet and the
// roadmap item that blocks it. It is coverage metadata only: nothing at scan
// time reads it, and it confers no runtime trust.
type PendingCMS struct {
	CMS    string `json:"cms"`
	Reason string `json:"reason"`
}

// Validate checks the manifest's own metadata: the version, every source's
// fields, and that every supported CMS is either sourced or explicitly
// pending, never both. The supported set always comes from internal/cms so a
// caller cannot validate against a smaller one. Archive authentication,
// extraction confinement and inventory checks stay in Prepare.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("corpus manifest version %d is not supported; version %d with a cms field on every source is required", m.Version, ManifestVersion)
	}
	if len(m.Sources) == 0 {
		return fmt.Errorf("corpus manifest has no source")
	}
	sourced := make(map[cms.Kind]bool)
	seenID := make(map[string]bool, len(m.Sources))
	for _, s := range m.Sources {
		if err := s.validate(); err != nil {
			return err
		}
		if seenID[s.ID] {
			return fmt.Errorf("source %q: id declared twice", s.ID)
		}
		seenID[s.ID] = true
		kind, ok := cms.Parse(s.CMS)
		if !ok {
			return fmt.Errorf("source %q: cms %q is not a supported kind", s.ID, s.CMS)
		}
		sourced[kind] = true
	}
	pending := make(map[cms.Kind]bool)
	for _, p := range m.Pending {
		kind, ok := cms.Parse(p.CMS)
		if !ok {
			return fmt.Errorf("pending cms %q is not a supported kind", p.CMS)
		}
		if pending[kind] {
			return fmt.Errorf("pending cms %q is declared twice", p.CMS)
		}
		if strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("pending cms %q: reason is required", p.CMS)
		}
		if sourced[kind] {
			return fmt.Errorf("cms %q is both sourced and pending", p.CMS)
		}
		pending[kind] = true
	}
	for _, d := range cms.All() {
		if !sourced[d.Kind] && !pending[d.Kind] {
			return fmt.Errorf("cms %q has neither a pinned source nor a pending entry", d.Kind)
		}
	}
	return nil
}

func (s Source) validate() error {
	if s.ID == "" || strings.ContainsAny(s.ID, "/\\\x00") || s.ID == "." || s.ID == ".." {
		return fmt.Errorf("source %q: id must be a non-empty path-safe name", s.ID)
	}
	if s.Version == "" || strings.ContainsAny(s.Version, "/\\\x00") {
		return fmt.Errorf("source %q: version must be a non-empty path-safe string", s.ID)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("source %q: url must be https with a host", s.ID)
	}
	digest, err := hex.DecodeString(s.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("source %q: sha256 must be 64 hex characters", s.ID)
	}
	if s.License == "" {
		return fmt.Errorf("source %q: license is required", s.ID)
	}
	if !filepath.IsLocal(s.LicenseFile) {
		return fmt.Errorf("source %q: license_file must be a local path inside the archive", s.ID)
	}
	if s.Files < 1 || s.Files > maxSourceFiles {
		return fmt.Errorf("source %q: files must be between 1 and %d", s.ID, maxSourceFiles)
	}
	if s.CMS == "" {
		return fmt.Errorf("source %q: cms field is required in manifest version %d", s.ID, ManifestVersion)
	}
	return nil
}

// maxSourceFiles bounds a pinned archive's inventory.
const maxSourceFiles = 30000

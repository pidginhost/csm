package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/store"
)

// ErrModSecReloadNotConfigured reports a CSM rule section that differs from
// the last one the web server reloaded, on a host with no reload command.
var ErrModSecReloadNotConfigured = errors.New("modsec.reload_command is not set, so CSM cannot confirm its updated ModSecurity rules are active; they apply at the next web server reload")

// modsecActiveSectionKey holds the hash of the CSM section on disk at the last
// successful reload. Comparing against it, rather than reloading when a write
// happens, also activates sections written by the installer or an upgrade.
const modsecActiveSectionKey = "modsec:active_section_sha256"

var modsecReloadRunner = modsec.Reload

// vpDestPaths are the ModSecurity user configuration files CSM writes its
// section into, in order of preference.
var vpDestPaths = []string{
	"/etc/apache2/conf.d/modsec/modsec2.user.conf",
	"/usr/local/apache/conf/modsec2.user.conf",
}

// ReconcileModSecReload reloads the web server when CSM's rule section differs
// from the one active after the last successful reload. ModSecurity reads its
// configuration only at start or reload, so a rewritten section does nothing
// until then.
func ReconcileModSecReload(reloadCommand string) error {
	db := store.Global()
	if db == nil {
		return nil
	}
	section, ok := installedVPSection()
	if !ok {
		return nil
	}
	sum := sha256.Sum256(section)
	digest := hex.EncodeToString(sum[:])
	if db.GetMetaString(modsecActiveSectionKey) == digest {
		return nil
	}
	if reloadCommand == "" {
		return ErrModSecReloadNotConfigured
	}
	if _, err := modsecReloadRunner(reloadCommand); err != nil {
		return fmt.Errorf("web server reload for CSM ModSecurity rules: %w", err)
	}
	csmlog.Info("web server reloaded to activate CSM ModSecurity rules", "command", reloadCommand)
	return db.SetMetaString(modsecActiveSectionKey, digest)
}

// installedVPSection returns CSM's delimited section from the first user
// configuration file that deployVirtualPatches would write.
func installedVPSection() ([]byte, bool) {
	for _, dest := range vpDestPaths {
		if _, err := osFS.Stat(filepath.Dir(dest)); os.IsNotExist(err) {
			continue
		}
		data, err := osFS.ReadFile(dest)
		if err != nil {
			return nil, false
		}
		begin, _, ok := markerLineBounds(data, vpBeginMarker)
		if !ok {
			return nil, false
		}
		end := vpSectionEnd(data[begin:])
		if end < 0 {
			return nil, false
		}
		return data[begin : begin+end], true
	}
	return nil, false
}

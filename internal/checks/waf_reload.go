package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

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

// ModSecReloadReconciler is owned by the daemon and shared by startup and all
// its scans. A CLI opening the store must not implicitly gain reload authority.
type ModSecReloadReconciler struct {
	mu      sync.Mutex
	db      *store.DB
	active  string
	pending bool // a successful reload whose metadata write needs retrying
}

type modsecReloadContextKey struct{}

// WithModSecReload lets daemon scans share their startup reconciler. Contexts
// without one can still deploy rules, but leave activation to the daemon.
func WithModSecReload(ctx context.Context, r *ModSecReloadReconciler) context.Context {
	return context.WithValue(ctx, modsecReloadContextKey{}, r)
}

func deployAndReconcileModSec(ctx context.Context, command string) error {
	r, _ := ctx.Value(modsecReloadContextKey{}).(*ModSecReloadReconciler)
	if r == nil {
		deployVirtualPatches()
		return nil
	}
	// Serialize the write as well as the reload: a concurrent scan must not
	// truncate the configuration while the web server is reading it.
	r.mu.Lock()
	defer r.mu.Unlock()
	deployVirtualPatches()
	if strings.TrimSpace(command) == "" {
		return nil // only startup warns about an unset command
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.reconcile(command)
}

// Reconcile activates sections already written by startup or the installer.
// Only failed reloads are repeated; metadata failures retry just the write.
func (r *ModSecReloadReconciler) Reconcile(reloadCommand string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reconcile(reloadCommand)
}

func (r *ModSecReloadReconciler) reconcile(reloadCommand string) error {
	db := store.Global()
	if db == nil {
		return nil
	}
	r.db = db
	digest, err := installedVPSectionDigest()
	if err != nil {
		return err
	}
	if digest == "" {
		return nil
	}
	if r.active == "" {
		active, err := db.ReadMetaString(modsecActiveSectionKey)
		if err != nil {
			return fmt.Errorf("read active CSM ModSecurity rules: %w", err)
		}
		r.active = active
	}
	if r.active == digest {
		return r.persistActive()
	}
	if strings.TrimSpace(reloadCommand) == "" {
		return ErrModSecReloadNotConfigured
	}
	if _, err := modsecReloadRunner(reloadCommand); err != nil {
		return fmt.Errorf("web server reload for CSM ModSecurity rules: %w", err)
	}
	r.active, r.pending = digest, true
	csmlog.Info("web server reloaded to activate CSM ModSecurity rules", "command", reloadCommand)
	return r.persistActive()
}

func (r *ModSecReloadReconciler) persistActive() error {
	if !r.pending {
		return nil
	}
	if err := r.db.SetMetaString(modsecActiveSectionKey, r.active); err != nil {
		return fmt.Errorf("web server reloaded, but recording active CSM ModSecurity rules failed: %w", err)
	}
	r.pending = false
	return nil
}

// Deployment can fall back when the preferred file cannot be written. Track
// every installed section so an older preferred copy cannot hide that update.
func installedVPSectionDigest() (string, error) {
	var sums []byte
	var readErr error
	for _, dest := range vpDestPaths {
		data, err := osFS.ReadFile(dest)
		if err != nil {
			if !os.IsNotExist(err) {
				readErr = errors.Join(readErr, fmt.Errorf("read CSM ModSecurity rules in %s: %w", dest, err))
			}
			continue
		}
		begin, _, ok := markerLineBounds(data, vpBeginMarker)
		if !ok {
			continue
		}
		end := vpSectionEnd(data[begin:])
		if end < 0 {
			readErr = errors.Join(readErr, fmt.Errorf("unterminated CSM ModSecurity section in %s", dest))
			continue
		}
		sum := sha256.Sum256(data[begin : begin+end])
		sums = append(sums, sum[:]...)
	}
	if len(sums) == 0 {
		return "", readErr
	}
	// The usual single section is identified by its own hash.
	if len(sums) == sha256.Size {
		return hex.EncodeToString(sums), nil
	}
	sum := sha256.Sum256(sums)
	return hex.EncodeToString(sum[:]), nil
}

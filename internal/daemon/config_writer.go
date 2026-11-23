package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// configWriteTimeout bounds one config save through the helper.
const configWriteTimeout = 30 * time.Second

var (
	configWriterLookPath systemdrun.LookPathFunc    = exec.LookPath
	configWriterRun      systemdrun.InputRunnerFunc = checks.RunWorkerCommand
)

// routeConfigWrites sends every config save the daemon makes (web UI
// settings, baseline, the reload re-sign) to csm config-write: the daemon's
// sandbox cannot write the config's directory.
func routeConfigWrites() {
	integrity.SetConfigWriter(func(c integrity.SignedConfig) error {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		return runConfigWriter(context.Background(), binary, configWriterLookPath, configWriterRun, c)
	})
}

// runConfigWriter runs the helper in a transient unit that can write only
// the directory the save changes. Without systemd-run there is no sandbox
// to leave, and the helper runs directly.
func runConfigWriter(ctx context.Context, binary string, lookPath systemdrun.LookPathFunc, run systemdrun.InputRunnerFunc, c integrity.SignedConfig) error {
	target, err := integrity.ResolveConfigWritePath(c.Path)
	if err != nil {
		return err
	}
	c.Path = target
	dir := filepath.Dir(target)
	// A unit property splits on whitespace and expands specifiers; refuse
	// rather than grant a different path.
	if strings.ContainsAny(dir, " \t\r\n\v\f\"'\\%;") {
		return fmt.Errorf("config directory %q cannot be named in a unit property", dir)
	}
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, configWriteTimeout)
	defer cancel()
	_, err = systemdrun.RunInput(ctx, lookPath, run, systemdrun.Options{
		RuntimeMax: configWriteTimeout,
		// PrivateTmp would hide configurations under /tmp or /var/tmp. The
		// read-only filesystem still limits writes to the resolved directory.
		Properties: []string{"ProtectSystem=strict", "ReadWritePaths=" + dir, "NoNewPrivileges=yes", "PrivateNetwork=yes", "PrivateTmp=no"},
	}, body, binary, integrity.ConfigWriteCommand)
	if err != nil {
		return fmt.Errorf("config writer: %w", err)
	}
	return nil
}

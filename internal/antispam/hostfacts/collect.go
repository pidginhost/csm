package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/platform"
)

// commandTimeout bounds each command (spec section 6.3 allows 10s for
// commands other than buildeximconf).
const commandTimeout = 10 * time.Second

// Layout holds the host files Collect reads.
type Layout struct {
	GeneratedConf string
	LocalConf     string
	SpamdDisabled string
	GlobalEnable  string
	Targets       []antispam.Target
}

type collector struct {
	layout   Layout
	cpanel   func() bool
	eximMTA  func() bool
	run      func(ctx context.Context, name string, args ...string) antispam.CommandResult
	lookPath func(string) (string, error)
	uid      func(name string) (int, error)
	gid      func(name string) (int, error)
}

func live() collector {
	return collector{
		layout: Layout{
			GeneratedConf: antispam.GeneratedEximConfPath,
			LocalConf:     antispam.LocalEximConfPath,
			SpamdDisabled: "/etc/spamddisable",
			GlobalEnable:  "/etc/global_spamassassin_enable",
			Targets:       antispam.MutationTargets(),
		},
		cpanel:   func() bool { return platform.Detect().IsCPanel() },
		eximMTA:  func() bool { return platform.DetectMTA() == platform.MTAExim },
		run:      runCommand,
		lookPath: exec.LookPath,
		uid:      lookupUID,
		gid:      lookupGID,
	}
}

// Collect reads every fact antispam.CheckHost evaluates for the scan socket.
// It changes nothing on the host.
func Collect(ctx context.Context, socket string) antispam.HostFacts {
	return live().collect(ctx, socket)
}

func (c collector) collect(ctx context.Context, socket string) antispam.HostFacts {
	f := antispam.HostFacts{CPanel: c.cpanel(), MTAExim: c.eximMTA(), MonitoredLog: platform.EximMainLog}
	f.EximVersion = c.run(ctx, "exim", "-bV")
	f.EximOptions = c.run(ctx, "exim", "-bP", "prdr_enable", "chunking_advertise_hosts")
	f.EximSettings = c.run(ctx, "exim", append([]string{"-bP"}, antispam.EximSettingNames()...)...)
	for _, probe := range antispam.NamedListProbes() {
		f.NamedLists = append(f.NamedLists, c.run(ctx, "exim", "-C", c.layout.GeneratedConf, "-be", probe))
	}
	f.RspamdVersion = c.run(ctx, "rspamd", "--version")
	f.RspamadmVersion = c.run(ctx, "rspamadm", "--version")
	f.RspamdOptions = c.run(ctx, "rspamadm", "configdump", "-j", "options")
	f.RspamdService = c.run(ctx, "systemctl", antispam.UnitShowArgs(antispam.RspamdUnit)...)
	f.EximService = c.run(ctx, "systemctl", antispam.UnitShowArgs(antispam.EximUnit)...)
	_, f.SystemdRunErr = c.lookPath("systemd-run")

	f.GeneratedConf, f.GeneratedErr = readText(c.layout.GeneratedConf)
	if f.LocalConf, f.LocalErr = readText(c.layout.LocalConf); errors.Is(f.LocalErr, fs.ErrNotExist) {
		f.LocalConf, f.LocalErr = "", nil
	}
	f.SpamdDisabled, f.SpamdDisabledErr = exists(c.layout.SpamdDisabled)
	f.GlobalEnable, _ = exists(c.layout.GlobalEnable)

	settings := map[string]string{}
	if f.EximSettings.Err == nil {
		settings = antispam.ParseEximOptions(f.EximSettings.Stdout)
	}
	if name := settings["system_filter"]; name != "" {
		f.SystemFilter, f.SystemFilterErr = readText(name)
	}
	for _, t := range c.layout.Targets {
		f.Targets = append(f.Targets, targetFacts(t))
	}

	f.Socket = socketFacts(ctx, socket)
	f.Socket.RspamdUID = c.serviceUser(f.RspamdService)
	f.Socket.EximUID = id(settings["exim_user"], c.uid)
	f.Socket.EximGID = id(settings["exim_group"], c.gid)
	return f
}

// serviceUser is the uid a loaded unit runs as: root without User=, -1 when
// unknown.
func (c collector) serviceUser(show antispam.CommandResult) int {
	props := antispam.ParseUnitShow(show.Stdout)
	switch {
	case show.Err != nil || props["LoadState"] != "loaded":
		return -1
	case props["User"] == "":
		return 0
	}
	return id(props["User"], c.uid)
}

// id resolves a user or group given by name or number, or returns -1.
func id(value string, lookup func(string) (int, error)) int {
	if value == "" {
		return -1
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		n, err = lookup(value)
	}
	if err != nil || n < 0 {
		return -1
	}
	return n
}

func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(u.Uid)
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

// runCommand runs one read-only command with its own time limit.
func runCommand(ctx context.Context, name string, args ...string) antispam.CommandResult {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tool names; arguments are constants, the validated config path or fixed probe expressions
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return antispam.CommandResult{Stdout: stdout.String(), Stderr: stderr.String(), Err: err}
}

func readText(p string) (string, error) {
	data, err := os.ReadFile(p) // #nosec G304 -- root-owned Exim configuration files
	return string(data), err
}

// exists reports whether p exists, following symlinks as cPanel's own -e test does.
func exists(p string) (bool, error) {
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

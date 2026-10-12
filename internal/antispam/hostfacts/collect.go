package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/platform"
)

// commandTimeout bounds each command (spec section 6.3 allows 10s for
// commands other than buildeximconf).
const commandTimeout = 10 * time.Second

// maxConfigBytes bounds each configuration file the collector reads; cPanel's
// generated exim.conf is under 100 KiB.
const maxConfigBytes = 16 << 20

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
	f.GlobalEnable, f.GlobalEnableErr = exists(c.layout.GlobalEnable)

	settings := map[string]string{}
	if f.EximSettings.Err == nil {
		settings = antispam.ParseEximOptions(f.EximSettings.Stdout)
	}
	name, known := settings["system_filter"]
	switch {
	case !known && f.EximSettings.Err == nil:
		f.SystemFilterErr = errors.New("exim -bP did not report system_filter")
	case name != "" && (!filepath.IsAbs(name) || strings.Contains(name, "$")):
		// The collector cannot reproduce Exim's delivery-time expansion
		// or working directory.
		f.SystemFilterErr = errors.New("system_filter is not a literal absolute path")
	case name != "":
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

// serviceUser returns the scanner uid, or -1 when it cannot be inferred.
// A root-started rspamd can select a different worker user with -u.
func (c collector) serviceUser(show antispam.CommandResult) int {
	props := antispam.ParseUnitShow(show.Stdout)
	if show.Err != nil || props["LoadState"] != "loaded" {
		return -1
	}
	uid := id(props["User"], c.uid)
	if uid == 0 {
		return -1
	}
	return uid
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
	// Opening a FIFO must not stall collection before its type is checked.
	file, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- paths come from the fixed layout or trusted Exim settings
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("configuration is not a regular file")
	}
	return readConfigContent(file)
}

func readConfigContent(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	switch {
	case err != nil:
		return "", err
	case len(data) > maxConfigBytes:
		return "", fmt.Errorf("configuration is larger than %d bytes", maxConfigBytes)
	}
	return string(data), nil
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

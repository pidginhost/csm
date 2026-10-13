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
	Record        string
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
			Record:        antispam.RecordPath,
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
	f.RspamdActions = c.run(ctx, "rspamadm", "configdump", "-j", "actions")
	f.RspamdModules = c.run(ctx, "rspamadm", "configdump", "-m")
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
	f.Targets = Targets(c.layout.Targets)
	f.Record = c.record()

	f.Socket = socketFacts(ctx, socket)
	f.Socket.RspamdUID = c.serviceUser(f.RspamdService)
	f.Socket.EximUID = id(settings["exim_user"], c.uid)
	f.Socket.EximGID = id(settings["exim_group"], c.gid)
	return f
}

// CollectInstalled reads only what shows whether CSM's integration is on
// the host: the files CSM writes, the generated Exim configuration and the
// completion record. It leaves other facts unset, including platform facts
// whose detection can run commands.
func CollectInstalled() antispam.HostFacts {
	return live().installed()
}

func (c collector) installed() antispam.HostFacts {
	var f antispam.HostFacts
	f.GeneratedConf, f.GeneratedErr = readText(c.layout.GeneratedConf)
	f.Targets = Targets(c.layout.Targets)
	f.Record = c.record()
	return f
}

func (c collector) record() antispam.RecordFacts {
	content, err := readRegularContent(c.layout.Record, antispam.MaxRecordBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return antispam.RecordFacts{Missing: true}
	}
	return antispam.RecordFacts{Content: content, Err: err}
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

func runCommand(ctx context.Context, name string, args ...string) antispam.CommandResult {
	return RunCommand(ctx, commandTimeout, name, args...)
}

// RunCommand runs one command with its own time limit. Standard input is
// /dev/null and output goes to fresh pipes, never the caller's streams.
func RunCommand(ctx context.Context, limit time.Duration, name string, args ...string) antispam.CommandResult {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tool names; arguments are constants, the validated config path or fixed probe expressions
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// A timed-out rebuild must not leave children writing during rollback.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err != nil && cmd.Process != nil {
		// A failing parent can exit while descendants still hold its pipes.
		if stopErr := cmd.Cancel(); stopErr != nil && !errors.Is(stopErr, os.ErrProcessDone) {
			err = errors.Join(err, stopErr)
		}
	}
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
	return readConfigContent(file, maxConfigBytes)
}

func readConfigContent(r io.Reader, maxBytes int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	switch {
	case err != nil:
		return "", err
	case int64(len(data)) > maxBytes:
		return "", fmt.Errorf("file is larger than %d bytes", maxBytes)
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

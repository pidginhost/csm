package hostfacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/ipmap"
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
	ResolvConf    string
	Targets       []antispam.Target
	// IPMap is the CSM IP map file rspamd reads.
	IPMap string
}

type collector struct {
	layout   Layout
	cpanel   func() bool
	eximMTA  func() bool
	run      func(ctx context.Context, name string, args ...string) antispam.CommandResult
	lookPath func(string) (string, error)
	uid      func(name string) (int, error)
	gid      func(name string) (int, error)
	userName func(uid string) (string, error)
	// primaryGID is a user's primary group.
	primaryGID func(user string) (int, error)
	// interfaceAddrs, readGroup and readPasswd feed controller exposure.
	interfaceAddrs func() ([]net.Addr, error)
	readGroup      func() ([]byte, error)
	readPasswd     func() ([]byte, error)
}

func live() collector {
	return collector{
		layout: Layout{
			GeneratedConf: antispam.GeneratedEximConfPath,
			LocalConf:     antispam.LocalEximConfPath,
			SpamdDisabled: "/etc/spamddisable",
			GlobalEnable:  "/etc/global_spamassassin_enable",
			Record:        antispam.RecordPath,
			ResolvConf:    "/etc/resolv.conf",
			Targets:       antispam.MutationTargets(),
			IPMap:         ipmap.DefaultPath,
		},
		cpanel:         func() bool { return platform.Detect().IsCPanel() },
		eximMTA:        func() bool { return platform.DetectMTA() == platform.MTAExim },
		run:            runCommand,
		lookPath:       exec.LookPath,
		uid:            lookupUID,
		gid:            lookupGID,
		userName:       lookupUserName,
		primaryGID:     lookupPrimaryGID,
		interfaceAddrs: net.InterfaceAddrs,
		readGroup:      func() ([]byte, error) { return readAccountFile("/etc/group") },
		readPasswd:     func() ([]byte, error) { return readAccountFile("/etc/passwd") },
	}
}

// RspamdGroup is rspamd's service group, or -1 when unknown (a root-started
// rspamd, or systemctl failing).
func RspamdGroup(ctx context.Context) int {
	c := live()
	return c.serviceGroup(c.run(ctx, "systemctl", antispam.UnitShowArgs(antispam.RspamdUnit)...))
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
	f.RspamdPhishing = c.run(ctx, "rspamadm", "configdump", "-j", "phishing")
	f.RspamdRBL = c.run(ctx, "rspamadm", "configdump", "-j", "rbl")
	f.RspamdConfig = c.run(ctx, "rspamadm", "configdump", "-j")
	f.RspamdLog = rspamdLog(f.RspamdConfig)
	f.IPMap = fileFacts(c.layout.IPMap)
	f.RspamdService = c.run(ctx, "systemctl", antispam.UnitShowArgs(antispam.RspamdUnit)...)
	f.EximService = c.run(ctx, "systemctl", antispam.UnitShowArgs(antispam.EximUnit)...)
	_, f.SystemdRunErr = c.lookPath("systemd-run")

	f.GeneratedConf, f.GeneratedErr = readText(c.layout.GeneratedConf)
	if f.LocalConf, f.LocalErr = readText(c.layout.LocalConf); errors.Is(f.LocalErr, fs.ErrNotExist) {
		f.LocalConf, f.LocalErr = "", nil
	}
	f.SpamdDisabled, f.SpamdDisabledErr = exists(c.layout.SpamdDisabled)
	f.GlobalEnable, f.GlobalEnableErr = exists(c.layout.GlobalEnable)
	f.ResolvConf, f.ResolvConfErr = readText(c.layout.ResolvConf)

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
	f.RspamdGID = c.serviceGroup(f.RspamdService)
	f.Socket.EximUID = id(settings["exim_user"], c.uid)
	f.Socket.EximGID = id(settings["exim_group"], c.gid)
	c.controllerFacts(&f)
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

// serviceGroup returns the rspamd service's group: the unit's Group, else
// the primary group of its User, else -1. A root-started rspamd drops to a
// user and group of its own choosing, so its group is unknown.
func (c collector) serviceGroup(show antispam.CommandResult) int {
	if c.serviceUser(show) < 0 {
		return -1
	}
	props := antispam.ParseUnitShow(show.Stdout)
	if g := props["Group"]; g != "" {
		return id(g, c.gid)
	}
	// A numeric User is a uid, not its primary gid.
	gid, err := c.primaryGID(props["User"])
	if err != nil || gid < 0 {
		return -1
	}
	return gid
}

func lookupPrimaryGID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		u, err = user.LookupId(name)
	}
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(u.Gid)
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

func lookupUserName(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
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

// rspamdLog reads rspamd's log destination from `rspamadm configdump -j`
// and, for a file, the file and its directories.
func rspamdLog(dump antispam.CommandResult) antispam.LogFacts {
	var out antispam.LogFacts
	var d struct {
		Logging struct {
			Type     string `json:"type"`
			Filename string `json:"filename"`
		} `json:"logging"`
	}
	if dump.Err != nil || json.Unmarshal([]byte(dump.Stdout), &d) != nil || d.Logging.Type == "" {
		out.Err = errors.New("rspamd's logging settings are not readable")
		return out
	}
	out.Type, out.Path = d.Logging.Type, d.Logging.Filename
	if out.Type != "file" {
		return out
	}
	if !filepath.IsAbs(out.Path) {
		out.Err = errors.New("rspamd's log file is not an absolute path")
		return out
	}
	if out.Parents, out.Err = chain(filepath.Dir(out.Path)); out.Err != nil {
		return out
	}
	switch facts, err := pathFacts(out.Path); {
	case errors.Is(err, fs.ErrNotExist):
		out.Missing = true
	case err != nil:
		out.Err = err
	default:
		out.File = facts
	}
	return out
}

// fileFacts records the file and its directories without following links.
func fileFacts(p string) antispam.FileFacts {
	var out antispam.FileFacts
	if out.Parents, out.Err = chain(filepath.Dir(p)); out.Err != nil {
		if errors.Is(out.Err, fs.ErrNotExist) {
			out.Missing, out.Err = true, nil
		}
		return out
	}
	if last := out.Parents[len(out.Parents)-1]; !last.Mode.IsDir() {
		out.Err = fmt.Errorf("%s is not a directory", last.Path)
		return out
	}
	switch facts, err := pathFacts(p); {
	case errors.Is(err, fs.ErrNotExist):
		out.Missing = true
	case err != nil:
		out.Err = err
	default:
		out.File = facts
	}
	return out
}

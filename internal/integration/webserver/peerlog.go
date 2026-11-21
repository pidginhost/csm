package webserver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"text/template"

	"github.com/pidginhost/csm/internal/platform"
)

// peerLogDir holds PeerLogFile, the log the snippet makes the web server
// write and the daemon read. It is not /var/log/csm: LiteSpeed's workers
// open the log by path, and CSM's own log directory admits root only.
const (
	peerLogDir  = "/var/log/csm-web"
	PeerLogFile = peerLogDir + "/peer.log"
)

// peerLogGroupFor is the group whose web server workers open the peer log by
// path: nobody for LiteSpeed on cPanel. Apache's root parent opens its logs
// itself, so there the directory stays root's.
func peerLogGroupFor(info platform.Info) string {
	if info.IsCPanel() && info.WebServer == platform.WSLiteSpeed {
		return "nobody"
	}
	return ""
}

// PeerLogPathFor is where the peer log snippet goes on hosts whose web
// server supports Apache log directives: Apache, and LiteSpeed reading
// cPanel's Apache tree. Keep the path on front-proxied hosts for removal
// of snippets installed before nginx was enabled. Elsewhere it is "".
func PeerLogPathFor(info platform.Info) string {
	switch {
	case info.IsCPanel() && (info.WebServer == platform.WSApache || info.WebServer == platform.WSLiteSpeed):
		return "/etc/apache2/conf.d/csm-peer-log.conf"
	case info.WebServer == platform.WSApache && info.IsDebianFamily():
		return "/etc/apache2/conf-enabled/csm-peer-log.conf"
	case info.WebServer == platform.WSApache:
		return "/etc/httpd/conf.d/csm-peer-log.conf"
	}
	return ""
}

// peerLogBody is the snippet: one line per request with its start time,
// the virtual host, the connection's peer and the client address the
// server logged. Apache needs GlobalLog for vhosts with their own logs;
// IfFile keeps a removed log directory from preventing server startup.
func (i *Installer) peerLogBody() ([]byte, error) {
	tpl, err := template.New("peerlog").Parse(peerLogTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(templateHeaderPrefix + strconv.Itoa(PeerLogTemplateVersion) + "\n")
	err = tpl.Execute(&b, struct {
		LogDir  string
		LogFile string
	}{i.PeerLogDir, filepath.Join(i.PeerLogDir, filepath.Base(PeerLogFile))})
	return b.Bytes(), err
}

func (i *Installer) peerLogResult(action string) Result {
	return Result{Action: action, Webserver: i.Handler.Kind(), SnippetPath: i.PeerLogPath, ShippedVer: PeerLogTemplateVersion}
}

// readPeerLog returns the snippet's bytes and whether it exists; an
// existing file without the managed header is the operator's.
func (i *Installer) readPeerLog() ([]byte, bool, error) {
	data, err := i.ReadAt(i.PeerLogPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	case parseHeaderVersion(data) == 0:
		return data, true, ErrManualEdits
	}
	return data, true, nil
}

// InstallPeerLog writes the peer log snippet, validates the web server
// configuration and reloads it, restoring the previous state on failure. It
// needs no challenge settings.
func (i *Installer) InstallPeerLog() (Result, error) {
	res := i.peerLogResult("install")
	if i.PeerLogPath == "" {
		res.Status, res.Message = "skipped", "the web peer log is not supported on this web server"
		return res, nil
	}
	if i.hostInfo.FrontProxied {
		res.Status, res.Message = "skipped", "nginx runs in front of the web server, so every peer is this server and the web peer log cannot tell clients apart"
		return res, nil
	}
	prev, existed, err := i.readPeerLog()
	if err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	// Prepare the directory even for a current or newer snippet: the server
	// skips or cannot open the log while it is missing or closed to it.
	dirCreated, dirChanged, err := i.preparePeerLogDir()
	if err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	// The optional ReadWritePaths grant cannot take effect in a daemon
	// namespace that predates the directory, even after a web server reload.
	if dirCreated {
		res.Message = "Restart CSM (systemctl restart csm.service): it can empty the new peer log only after a restart."
	}
	// Never downgrade a snippet a newer CSM wrote.
	if v := parseHeaderVersion(prev); existed && v >= PeerLogTemplateVersion {
		res.Status, res.OnDiskVer = "no-op", v
		if dirChanged {
			if applyErr := i.applyPeerLog(prev, true); applyErr != nil {
				res.Status, res.Message = "fail", applyErr.Error()
				return res, applyErr
			}
			res.Status = "ok"
		}
		return res, nil
	}
	body, err := i.peerLogBody()
	if err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	if err := i.MkdirAll(filepath.Dir(i.PeerLogPath), 0o755); err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	if err := i.WriteAt(i.PeerLogPath, body, 0o644); err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	if err := i.applyPeerLog(prev, existed); err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	res.Status, res.OnDiskVer = "ok", PeerLogTemplateVersion
	return res, nil
}

// preparePeerLogDir makes the log directory 0750 with the web server's group,
// so its workers can open the log and other local users cannot, and reports
// whether it created the directory and whether it changed anything the
// running server may have missed.
func (i *Installer) preparePeerLogDir() (created, changed bool, err error) {
	info, lerr := i.LstatAt(i.PeerLogDir)
	if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
		return false, false, lerr
	}
	created = info == nil
	if info != nil && !info.IsDir() {
		return false, false, fmt.Errorf("peer log directory %s is not a directory", i.PeerLogDir)
	}
	gid := 0
	if i.PeerLogGroup != "" {
		g, lookupErr := user.LookupGroup(i.PeerLogGroup)
		if lookupErr != nil {
			return false, false, fmt.Errorf("web server group %s: %w", i.PeerLogGroup, lookupErr)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return false, false, fmt.Errorf("web server group %s: %w", i.PeerLogGroup, err)
		}
	}
	changed = info == nil || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o750 || !peerLogDirOwner(info, gid)
	if !changed {
		return false, false, nil
	}
	// The parent is root-owned /var/log. Close access before replacing the
	// owner and group so a failed chown cannot expose logs to the old group.
	if err = i.MkdirAll(i.PeerLogDir, 0o700); err != nil {
		return false, false, err
	}
	if err = i.ChmodAt(i.PeerLogDir, 0o700); err != nil {
		return false, false, err
	}
	if err = i.ChownAt(i.PeerLogDir, 0, gid); err != nil {
		return false, false, err
	}
	if err = i.ChmodAt(i.PeerLogDir, 0o750); err != nil {
		return false, false, err
	}
	return created, true, nil
}

func peerLogDirOwner(info os.FileInfo, gid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && int(st.Gid) == gid
}

// RemovePeerLog removes a managed peer log snippet and reloads.
func (i *Installer) RemovePeerLog() (Result, error) {
	res := i.peerLogResult("remove")
	if i.PeerLogPath == "" {
		res.Status = "skipped"
		return res, nil
	}
	prev, existed, err := i.readPeerLog()
	if err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	if !existed {
		res.Status = "no-op"
		return res, nil
	}
	if err := i.RemoveAt(i.PeerLogPath); err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	if err := i.applyPeerLog(prev, true); err != nil {
		res.Status, res.Message = "fail", err.Error()
		return res, err
	}
	res.Status = "ok"
	return res, nil
}

// PeerLogStatus reports whether the snippet is installed and current.
func (i *Installer) PeerLogStatus() (Result, error) {
	res := i.peerLogResult("status")
	if i.PeerLogPath == "" {
		res.Status = "skipped"
		return res, nil
	}
	data, existed, err := i.readPeerLog()
	switch {
	case errors.Is(err, ErrManualEdits):
		res.Status, res.Message = "manual", err.Error()
		return res, nil
	case err != nil:
		res.Status, res.Message = "fail", err.Error()
		return res, err
	case !existed:
		res.Status = "missing"
		return res, nil
	}
	res.OnDiskVer = parseHeaderVersion(data)
	res.Status = "ok"
	if res.OnDiskVer < PeerLogTemplateVersion {
		res.Status = "stale"
	}
	return res, nil
}

// applyPeerLog validates and reloads after a change to the snippet; on a
// failure it puts back prev (or removes the file when there was none) and,
// when the reload itself failed, reloads the restored configuration.
func (i *Installer) applyPeerLog(prev []byte, existed bool) error {
	restore := func() error {
		if existed {
			return i.WriteAt(i.PeerLogPath, prev, 0o644)
		}
		if err := i.RemoveAt(i.PeerLogPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := i.Handler.Validate(); err != nil {
		return errors.Join(fmt.Errorf("configtest refused the peer log change: %w", err), restore())
	}
	if err := i.Handler.Reload(); err != nil {
		rollback := restore()
		if rollback == nil {
			if validateErr := i.Handler.Validate(); validateErr != nil {
				rollback = fmt.Errorf("rollback configtest: %w", validateErr)
			} else if reloadErr := i.Handler.Reload(); reloadErr != nil {
				rollback = fmt.Errorf("recovery reload: %w", reloadErr)
			}
		}
		return errors.Join(fmt.Errorf("reload after the peer log change failed: %w", err), rollback)
	}
	return nil
}

// Run performs one challenge integration verb. The web peer log has its own
// verbs (RunPeerLog); upgrade only refreshes a peer log already installed.
func (i *Installer) Run(verb string) (Result, error) {
	switch verb {
	case "install":
		return i.Install()
	case "upgrade":
		res, err := i.Upgrade()
		st, statusErr := i.PeerLogStatus()
		if statusErr != nil {
			res.PeerLog = &st
			return res, errors.Join(err, statusErr)
		}
		if st.Status == "ok" || st.Status == "stale" {
			peer, peerErr := i.InstallPeerLog()
			res.PeerLog = &peer
			err = errors.Join(err, peerErr)
		}
		return res, err
	case "status":
		return i.Status()
	case "validate":
		return i.Validate()
	case "remove":
		return i.Remove()
	}
	return Result{Action: verb, Status: "fail"}, fmt.Errorf("webserver integration: unknown verb %q", verb)
}

// RunPeerLog performs one web peer log verb: install, status or remove. It
// needs no challenge settings.
func (i *Installer) RunPeerLog(verb string) (Result, error) {
	var (
		res Result
		err error
	)
	switch verb {
	case "install":
		res, err = i.InstallPeerLog()
	case "status":
		res, err = i.PeerLogStatus()
	case "remove":
		res, err = i.RemovePeerLog()
	default:
		return Result{Action: "peer-log " + verb, Status: "fail"}, fmt.Errorf("webserver integration: unknown peer-log verb %q", verb)
	}
	res.Action = "peer-log " + verb
	return res, err
}

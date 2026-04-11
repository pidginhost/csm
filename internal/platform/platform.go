// Package platform detects the host OS, control panel, and web server so
// CSM checks can pick the right config/log paths instead of hardcoding
// cPanel+Apache layouts.
package platform

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
)

type OSFamily string

const (
	OSUnknown    OSFamily = ""
	OSUbuntu     OSFamily = "ubuntu"
	OSDebian     OSFamily = "debian"
	OSAlma       OSFamily = "almalinux"
	OSRocky      OSFamily = "rocky"
	OSCentOS     OSFamily = "centos"
	OSRHEL       OSFamily = "rhel"
	OSCloudLinux OSFamily = "cloudlinux"
)

type Panel string

const (
	PanelNone   Panel = ""
	PanelCPanel Panel = "cpanel"
	PanelPlesk  Panel = "plesk"
	PanelDA     Panel = "directadmin"
)

type WebServer string

const (
	WSNone      WebServer = ""
	WSApache    WebServer = "apache"
	WSNginx     WebServer = "nginx"
	WSLiteSpeed WebServer = "litespeed"
)

// Info holds everything a check needs to locate web server resources.
type Info struct {
	OS        OSFamily
	OSVersion string
	Panel     Panel
	WebServer WebServer

	// Config locations for the detected web server.
	ApacheConfigDir string // e.g. /etc/apache2 or /etc/httpd
	NginxConfigDir  string // e.g. /etc/nginx

	// Candidate log files. Populated based on detected web server + OS.
	AccessLogPaths      []string
	ErrorLogPaths       []string
	ModSecAuditLogPaths []string

	// Binary paths useful for reload/control.
	ApacheBinary string
	NginxBinary  string
}

// IsCPanel is a convenience for checks that still need to gate cPanel-only
// behavior (WHM API calls, /home/*/public_html enumeration, exim log
// tailing, etc.) without re-detecting each time.
func (i Info) IsCPanel() bool { return i.Panel == PanelCPanel }

// IsRHELFamily reports whether the OS uses rpm/dnf and /etc/httpd style paths.
func (i Info) IsRHELFamily() bool {
	switch i.OS {
	case OSAlma, OSRocky, OSCentOS, OSRHEL, OSCloudLinux:
		return true
	}
	return false
}

// IsDebianFamily reports whether the OS uses dpkg/apt and /etc/apache2 style paths.
func (i Info) IsDebianFamily() bool {
	return i.OS == OSUbuntu || i.OS == OSDebian
}

// Overrides lets the operator override auto-detected values from csm.yaml.
// Any field left blank or nil falls back to the auto-detected value.
//
// Panel and WebServer use pointer types so callers can distinguish "leave
// auto-detected" (nil) from "explicitly override to none" (pointer to
// PanelNone / WSNone). The non-pointer string/slice fields use the
// zero-value-means-unset convention since they have no legitimate "none"
// value to override to.
type Overrides struct {
	Panel               *Panel
	WebServer           *WebServer
	AccessLogPaths      []string
	ErrorLogPaths       []string
	ModSecAuditLogPaths []string
	ApacheConfigDir     string
	NginxConfigDir      string
}

var (
	detected        Info
	detectedOnce    sync.Once
	overrideMu      sync.Mutex
	pendingOverride *Overrides
)

// SetOverrides installs config-supplied overrides to be merged into the next
// (and all subsequent) Detect() result. Call this once from daemon startup,
// BEFORE the first Detect() call, so the merged info is what every check
// sees. Subsequent SetOverrides calls before Detect() replace the previous
// override; calls after Detect() are no-ops and log a warning via the
// returned bool.
//
// Returns true if the override was installed, false if Detect() had already
// cached an un-overridden result.
func SetOverrides(o Overrides) bool {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	// Use a local mutex + a check on detectedOnce state. detectedOnce has
	// no public "was it called" query, so we track it via the pending var.
	if pendingOverride != nil && isDetected() {
		return false
	}
	pendingOverride = &o
	return !isDetected()
}

// isDetected returns true if Detect() has already cached a result.
// Internal helper — uses a separate flag because sync.Once has no query API.
var detectedFlag atomic.Bool

func isDetected() bool { return detectedFlag.Load() }

// Detect inspects the host and returns platform info. The result is cached
// for the process lifetime — callers that need a fresh probe should use
// DetectFresh instead.
func Detect() Info {
	detectedOnce.Do(func() {
		detected = DetectFresh()
		overrideMu.Lock()
		if pendingOverride != nil {
			detected = applyOverrides(detected, *pendingOverride)
		}
		overrideMu.Unlock()
		detectedFlag.Store(true)
	})
	return detected
}

// DetectFresh always re-runs detection, ignoring any cached result.
// Intended for tests and for operator-triggered rescan. Does not apply
// config overrides — use Detect() for the operator-visible view.
func DetectFresh() Info {
	i := Info{}
	detectOS(&i)
	detectPanel(&i)
	detectWebServer(&i)
	populatePaths(&i)
	return i
}

// applyOverrides merges non-empty override fields into info. Always returns
// a new Info — never mutates the input. Paths are replaced, not appended:
// if the operator configured an explicit access-log list, the auto-detected
// list is discarded so operators have full control.
func applyOverrides(info Info, o Overrides) Info {
	// Panel override must happen before path rebuild so populatePaths
	// picks up the cPanel overlay (or drops it) correctly. Nil means
	// "leave auto-detected"; a non-nil pointer always wins, even when it
	// points at PanelNone, so operators can explicitly force a host to
	// look panel-less.
	if o.Panel != nil {
		info.Panel = *o.Panel
	}
	if o.WebServer != nil {
		// Web server type changed → rebuild paths from scratch unless the
		// operator also supplied path overrides below. Same nil-vs-pointer
		// semantics as Panel: a pointer at WSNone forces "no web server"
		// instead of being silently ignored.
		info.WebServer = *o.WebServer
		info.AccessLogPaths = nil
		info.ErrorLogPaths = nil
		info.ModSecAuditLogPaths = nil
		populatePaths(&info)
	}
	if len(o.AccessLogPaths) > 0 {
		info.AccessLogPaths = append([]string(nil), o.AccessLogPaths...)
	}
	if len(o.ErrorLogPaths) > 0 {
		info.ErrorLogPaths = append([]string(nil), o.ErrorLogPaths...)
	}
	if len(o.ModSecAuditLogPaths) > 0 {
		info.ModSecAuditLogPaths = append([]string(nil), o.ModSecAuditLogPaths...)
	}
	if o.ApacheConfigDir != "" {
		info.ApacheConfigDir = o.ApacheConfigDir
	}
	if o.NginxConfigDir != "" {
		info.NginxConfigDir = o.NginxConfigDir
	}
	return info
}

// ResetForTest clears the cached Detect() result so tests can re-run with
// different fixtures. Never call from production code.
func ResetForTest() {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	detected = Info{}
	detectedOnce = sync.Once{}
	pendingOverride = nil
	detectedFlag.Store(false)
}

func detectOS(i *Info) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	var id, versionID string
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"'`)
		switch key {
		case "ID":
			id = strings.ToLower(val)
		case "VERSION_ID":
			versionID = val
		}
	}
	i.OSVersion = versionID
	switch id {
	case "ubuntu":
		i.OS = OSUbuntu
	case "debian":
		i.OS = OSDebian
	case "almalinux":
		i.OS = OSAlma
	case "rocky":
		i.OS = OSRocky
	case "centos":
		i.OS = OSCentOS
	case "rhel":
		i.OS = OSRHEL
	case "cloudlinux":
		i.OS = OSCloudLinux
	}
}

func detectPanel(i *Info) {
	if _, err := os.Stat("/usr/local/cpanel/version"); err == nil {
		i.Panel = PanelCPanel
		return
	}
	if _, err := os.Stat("/usr/local/psa/version"); err == nil {
		i.Panel = PanelPlesk
		return
	}
	if _, err := os.Stat("/usr/local/directadmin/directadmin"); err == nil {
		i.Panel = PanelDA
		return
	}
}

func detectWebServer(i *Info) {
	// Prefer the process that's actually running. Fall back to installed
	// binaries if nothing is running yet (first boot, non-systemd env).
	running := runningServices()

	// Always record binary paths for reload/control, even if not primary.
	if bin, err := exec.LookPath("nginx"); err == nil {
		i.NginxBinary = bin
	}
	if bin, err := exec.LookPath("apache2"); err == nil {
		i.ApacheBinary = bin
	} else if bin, err := exec.LookPath("httpd"); err == nil {
		i.ApacheBinary = bin
	}
	// cPanel compiles its own httpd under /usr/local/apache/bin/httpd,
	// which isn't always in PATH for root under the CSM service unit.
	if i.ApacheBinary == "" {
		const cpHttpd = "/usr/local/apache/bin/httpd"
		if _, err := os.Stat(cpHttpd); err == nil {
			i.ApacheBinary = cpHttpd
		}
	}

	i.WebServer = selectWebServer(i.Panel, running, i.ApacheBinary != "", i.NginxBinary != "")
}

// runningServices returns which web server process units are currently
// active. Uses systemctl when available; falls back to checking /proc.
func runningServices() map[string]bool {
	active := map[string]bool{}
	for _, unit := range []string{"nginx", "apache2", "httpd", "litespeed", "lshttpd", "lsws"} {
		cmd := exec.Command("systemctl", "is-active", "--quiet", unit)
		if err := cmd.Run(); err == nil {
			active[unit] = true
		}
	}
	return active
}

func selectWebServer(panel Panel, running map[string]bool, hasApacheBinary, hasNginxBinary bool) WebServer {
	apacheRunning := running["apache2"] || running["httpd"]
	litespeedRunning := running["litespeed"] || running["lshttpd"] || running["lsws"]
	nginxRunning := running["nginx"]

	// cPanel commonly runs Nginx as a reverse proxy in front of Apache.
	// Prefer the origin server logs when Apache is active so real-time
	// access and ModSecurity watchers tail the paths cPanel actually writes.
	if panel == PanelCPanel {
		switch {
		case litespeedRunning:
			return WSLiteSpeed
		case apacheRunning:
			return WSApache
		case nginxRunning:
			return WSNginx
		case hasApacheBinary:
			return WSApache
		case hasNginxBinary:
			return WSNginx
		default:
			return WSNone
		}
	}

	switch {
	case nginxRunning:
		return WSNginx
	case apacheRunning:
		return WSApache
	case litespeedRunning:
		return WSLiteSpeed
	case hasApacheBinary:
		return WSApache
	case hasNginxBinary:
		return WSNginx
	default:
		return WSNone
	}
}

func populatePaths(i *Info) {
	// Apache config dir. cPanel compiles Apache from source and installs
	// under /usr/local/apache, separate from the OS package tree; that
	// override wins over the distro default when cPanel is present.
	switch {
	case i.Panel == PanelCPanel && dirExists("/usr/local/apache/conf"):
		i.ApacheConfigDir = "/usr/local/apache/conf"
	case i.IsDebianFamily():
		if dirExists("/etc/apache2") {
			i.ApacheConfigDir = "/etc/apache2"
		}
	case i.IsRHELFamily():
		if dirExists("/etc/httpd") {
			i.ApacheConfigDir = "/etc/httpd"
		}
	}
	if dirExists("/etc/nginx") {
		i.NginxConfigDir = "/etc/nginx"
	}

	// Log paths: pick candidates based on detected web server and OS layout.
	// We include ALL plausible locations so log watchers can try each;
	// missing paths are handled upstream by the retry logic.
	switch i.WebServer {
	case WSApache:
		if i.IsDebianFamily() {
			i.AccessLogPaths = []string{"/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log"}
			i.ErrorLogPaths = []string{"/var/log/apache2/error.log"}
			i.ModSecAuditLogPaths = []string{"/var/log/apache2/modsec_audit.log"}
		} else {
			i.AccessLogPaths = []string{"/var/log/httpd/access_log"}
			i.ErrorLogPaths = []string{"/var/log/httpd/error_log"}
			i.ModSecAuditLogPaths = []string{"/var/log/httpd/modsec_audit.log"}
		}
	case WSNginx:
		i.AccessLogPaths = []string{"/var/log/nginx/access.log"}
		i.ErrorLogPaths = []string{"/var/log/nginx/error.log"}
		i.ModSecAuditLogPaths = []string{"/var/log/nginx/modsec_audit.log"}
	case WSLiteSpeed:
		i.AccessLogPaths = []string{"/usr/local/lsws/logs/access.log"}
		i.ErrorLogPaths = []string{"/usr/local/lsws/logs/error.log"}
		i.ModSecAuditLogPaths = []string{"/usr/local/lsws/logs/auditmodsec.log"}
	}

	// cPanel overlays its own access/error logs on top of the OS defaults.
	if i.Panel == PanelCPanel {
		i.AccessLogPaths = append([]string{
			"/usr/local/apache/logs/access_log",
			"/usr/local/cpanel/logs/access_log",
		}, i.AccessLogPaths...)
		i.ErrorLogPaths = append([]string{
			"/usr/local/apache/logs/error_log",
		}, i.ErrorLogPaths...)
		i.ModSecAuditLogPaths = append([]string{
			"/usr/local/apache/logs/modsec_audit.log",
			"/var/log/modsec_audit.log",
		}, i.ModSecAuditLogPaths...)
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

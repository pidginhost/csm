package checks

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// userdataDomainsPath is cPanel's authoritative domain->docroot map. It covers
// addon and subdomain docroots that /home/*/public_html misses.
const userdataDomainsPath = "/etc/userdatadomains"
const cpanelInstallPath = "/usr/local/cpanel"

// Bounds so the deep scan stays cheap on a host with hundreds of docroots.
const (
	exposureMaxFilesPerRoot   = 4000
	exposureMaxDirsPerRoot    = 4000
	exposureProbeConnTimeout  = 4 * time.Second
	exposureProbeTotalTimeout = 6 * time.Second
)

// walkSkipDirs are directory names never worth descending for a leaked dump or
// backup and expensive to traverse.
var walkSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".svn": true,
}

// CheckExposedFiles scans every cPanel docroot for sensitive files (database
// dumps, backup archives, config/source backups, phpinfo) that the web server
// actually serves, and reports each confirmed exposure. It reads only response
// headers except for a bounded phpinfo body used to reject empty stubs.
func CheckExposedFiles(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		// Absence is an expected no-op only on a non-cPanel host. Other failures
		// make the run incomplete: retaining prior findings is safer than
		// clearing them because the map was temporarily unreadable.
		if vhostMapFailureIsIncomplete(err) {
			markCheckIncomplete(ctx, "exposed_files")
		}
		return nil
	}
	vhosts, complete := parseUserdataDomainsChecked(string(content))
	if !complete {
		markCheckIncomplete(ctx, "exposed_files")
	}
	return scanVhostsForExposure(ctx, dedupVhostsByDocroot(vhosts), cfg)
}

func vhostMapFailureIsIncomplete(readErr error) bool {
	if !errors.Is(readErr, fs.ErrNotExist) {
		return true
	}
	_, statErr := osFS.Stat(cpanelInstallPath)
	// A missing map is an expected no-op only when cPanel itself is absent.
	// If the install path exists (or cannot be checked), preserve prior
	// findings until the authoritative map is readable again.
	return statErr == nil || !errors.Is(statErr, fs.ErrNotExist)
}

// dedupVhostsByDocroot keeps one vhost per docroot (multiple domains -- www,
// parked -- can share a docroot; one probe host is enough). Prefer a vhost with
// a usable serving IP, then a real main/addon/subdomain over a parked alias,
// since parked domains commonly redirect and cannot confirm an exposure.
func dedupVhostsByDocroot(vhosts []vhost) []vhost {
	chosen := make(map[string]int, len(vhosts))
	out := vhosts[:0:0]
	for _, vh := range vhosts {
		key := filepath.Clean(vh.docroot)
		if i, ok := chosen[key]; ok {
			if betterProbeVhost(vh, out[i]) {
				out[i] = vh
			}
			continue
		}
		chosen[key] = len(out)
		out = append(out, vh)
	}
	return out
}

func betterProbeVhost(candidate, current vhost) bool {
	candidateUsable := probeHost(candidate) != ""
	currentUsable := probeHost(current) != ""
	if candidateUsable != currentUsable {
		return candidateUsable
	}
	return preferredProbeVhost(candidate) && !preferredProbeVhost(current)
}

func preferredProbeVhost(vh vhost) bool {
	switch strings.ToLower(strings.TrimSpace(vh.typ)) {
	case "main", "addon", "sub":
		return true
	default:
		return false
	}
}

// scanVhostsForExposure walks each vhost's docroot, classifies candidate files,
// confirms the server serves them, and emits a finding per confirmed exposure.
func scanVhostsForExposure(ctx context.Context, vhosts []vhost, cfg *config.Config) []alert.Finding {
	depth := exposureScanDepth(cfg)
	var findings []alert.Finding
	for _, vh := range vhosts {
		if ctx.Err() != nil {
			return findings
		}
		host := probeHost(vh)
		if host == "" {
			// A loopback fallback is not a meaningful reachability check:
			// LiteSpeed rejects loopback-originated requests even when the same
			// vhost serves the file on its configured address. Skip this vhost
			// and preserve findings from the last complete scan instead.
			markCheckIncomplete(ctx, "exposed_files")
			continue
		}
		paths, complete := walkExposureCandidates(ctx, vh.docroot, depth)
		if !complete {
			markCheckIncomplete(ctx, "exposed_files")
		}
		for _, path := range paths {
			if ctx.Err() != nil {
				return findings
			}
			class := classifyExposedFile(filepath.Base(path))
			if class == classNone {
				continue
			}
			rel := relURLPath(vh.docroot, path)
			if rel == "" {
				continue
			}
			class = demoteSampleSQL(class, rel)
			pr := webProber.probe(ctx, vh.domain, host, rel)
			confirmed := confirmExposure(class, pr)
			if !confirmed && (!pr.reachable || pr.partial) {
				// A transport failure cannot prove that a previous exposure was
				// fixed. Keep prior findings until a later probe gets a response.
				markCheckIncomplete(ctx, "exposed_files")
			}
			if !confirmed {
				continue
			}
			if class == classPHPInfo {
				// Headers cannot distinguish a real dump from a stub whose
				// phpinfo() call is commented out or guarded: both answer 200
				// text/html. Only a body carrying actual phpinfo output is an
				// information disclosure.
				scheme, exposed, complete := confirmPHPInfoBody(ctx, pr.scheme, vh.domain, host, rel)
				if !complete {
					markCheckIncomplete(ctx, "exposed_files")
				}
				if !exposed {
					continue
				}
				pr.scheme = scheme
			}
			findings = append(findings, buildExposedFinding(vh, path, rel, class, pr))
		}
	}
	return findings
}

func exposureScanDepth(cfg *config.Config) int {
	depth := config.DefaultExposedFileScanDepth
	if cfg != nil && cfg.Thresholds.ExposedFileScanDepth > 0 {
		depth = cfg.Thresholds.ExposedFileScanDepth
	}
	if depth > config.MaxExposedFileScanDepth {
		return config.MaxExposedFileScanDepth
	}
	return depth
}

// walkExposureCandidates returns files under docroot down to maxDepth directory
// levels, capped at exposureMaxFilesPerRoot to bound I/O on large trees. It
// visits shallower directories first so a large cache subtree cannot consume
// the cap before root-level leaks are considered.
func walkExposureCandidates(ctx context.Context, docroot string, maxDepth int) ([]string, bool) {
	return walkExposureCandidatesLimit(ctx, docroot, maxDepth, exposureMaxFilesPerRoot)
}

func walkExposureCandidatesLimit(ctx context.Context, docroot string, maxDepth, maxFiles int) ([]string, bool) {
	if maxFiles <= 0 {
		return nil, false
	}
	type pendingDir struct {
		path  string
		depth int
	}
	queue := []pendingDir{{path: docroot}}
	queuedDirs := 1
	var out []string
	complete := true
	for len(queue) > 0 && len(out) < maxFiles {
		if ctx.Err() != nil {
			return out, false
		}
		dir := queue[0]
		queue = queue[1:]
		entries, err := osFS.ReadDir(dir.path)
		if err != nil {
			complete = false
			continue
		}
		for _, e := range entries {
			if ctx.Err() != nil {
				return out, false
			}
			if len(out) >= maxFiles {
				complete = false
				break
			}
			if e.IsDir() {
				if dir.depth < maxDepth && !walkSkipDirs[e.Name()] {
					if queuedDirs >= exposureMaxDirsPerRoot {
						complete = false
						continue
					}
					queue = append(queue, pendingDir{
						path:  filepath.Join(dir.path, e.Name()),
						depth: dir.depth + 1,
					})
					queuedDirs++
				}
				continue
			}
			out = append(out, filepath.Join(dir.path, e.Name()))
		}
	}
	if len(queue) > 0 {
		complete = false
	}
	return out, complete
}

func relURLPath(docroot, path string) string {
	r, err := filepath.Rel(docroot, path)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return ""
	}
	return "/" + filepath.ToSlash(r)
}

func buildExposedFinding(vh vhost, path, rel string, class exposedClass, pr probeResult) alert.Finding {
	size := int64(-1)
	if fi, err := osFS.Stat(path); err == nil {
		size = fi.Size()
	}
	scheme := pr.scheme
	if scheme == "" {
		scheme = "https"
	}
	exposureURL := (&url.URL{Scheme: scheme, Host: vh.domain, Path: rel}).String()
	return alert.Finding{
		Severity: class.severity(),
		Check:    class.findingName(),
		Message:  fmt.Sprintf("Web-exposed %s reachable at %s", exposureLabel(class), exposureURL),
		Details: fmt.Sprintf("File: %s (%d bytes), served as %q. Remove it from the web root or deny HTTP access.",
			path, size, pr.contentType),
		FilePath:  path,
		Domain:    vh.domain,
		TenantID:  vh.user,
		Timestamp: time.Now(),
	}
}

func exposureLabel(class exposedClass) string {
	switch class {
	case classConfigLeak:
		return "configuration/credentials file"
	case classDBDump:
		return "database dump"
	case classBackupArchive:
		return "site backup archive"
	case classSourceBackup:
		return "source-code backup"
	case classPHPInfo:
		return "phpinfo diagnostic"
	case classSampleSQL:
		return "framework/sample SQL file"
	default:
		return "sensitive file"
	}
}

// ---------------------------------------------------------------------------
// Reachability probe seam
// ---------------------------------------------------------------------------

// webProbe abstracts a headers-only reachability check against the local web
// server. Tests inject a fake; production pins the connection to the vhost's
// serving IP while using its domain as SNI/Host, and reads only the status line
// and Content-Type.
type webProbe interface {
	probe(ctx context.Context, domain, host, urlPath string) probeResult
}

var webProber webProbe = realWebProbe{}

// SetWebProbe replaces the reachability prober. Test-only seam.
func SetWebProbe(p webProbe) { webProber = p }

type realWebProbe struct{}

func (realWebProbe) probe(ctx context.Context, domain, host, urlPath string) probeResult {
	results := make([]probeResult, 0, 2)
	partial := false
	for _, scheme := range []string{"https", "http"} {
		if pr, ok := doLocalProbe(ctx, scheme, domain, host, urlPath); ok {
			results = append(results, pr)
			// A successful non-HTML response is sufficient for every raw
			// leak class; avoid an unnecessary second request.
			if successfulProbe(pr) && !isHTMLContentType(pr.contentType) {
				return pr
			}
		} else {
			partial = true
		}
	}
	pr := bestProbeResult(results)
	pr.partial = partial
	return pr
}

func successfulProbe(pr probeResult) bool {
	return pr.status == http.StatusOK || pr.status == http.StatusPartialContent
}

// bestProbeResult prefers a successful response over an HTTP error and a raw
// response over HTML. This lets an HTTP-only exposure win when HTTPS redirects,
// blocks the path, or executes a different handler.
func bestProbeResult(results []probeResult) probeResult {
	var firstReachable probeResult
	var firstSuccess probeResult
	for _, pr := range results {
		if !pr.reachable {
			continue
		}
		if !firstReachable.reachable {
			firstReachable = pr
		}
		if !successfulProbe(pr) {
			continue
		}
		if !isHTMLContentType(pr.contentType) {
			return pr
		}
		if !firstSuccess.reachable {
			firstSuccess = pr
		}
	}
	if firstSuccess.reachable {
		return firstSuccess
	}
	return firstReachable
}

// doLocalProbe issues one HEAD (falling back to a ranged GET when HEAD is
// disallowed) to the vhost's own serving IP, presenting domain as the vhost. It
// never reads the response body. The dial is pinned to the host's configured
// serving address (never DNS-resolved) so the request reaches this origin, not
// a CDN, and stays on-box. Loopback is not used: LiteSpeed answers 403 to
// loopback-originated requests even for files it serves on the public IP.
func doLocalProbe(ctx context.Context, scheme, domain, host, urlPath string) (probeResult, bool) {
	host = normalizeServingIP(host)
	if host == "" {
		return probeResult{}, false
	}
	probeCtx, cancel := context.WithTimeout(ctx, exposureProbeTotalTimeout)
	defer cancel()
	client, closeIdle := exposureProbeHTTPClient(domain, host)
	defer closeIdle()
	return doLocalProbeWithClient(probeCtx, client, scheme, domain, urlPath)
}

func doLocalProbeWithClient(ctx context.Context, client *http.Client, scheme, domain, urlPath string) (probeResult, bool) {
	u := url.URL{Scheme: scheme, Host: domain, Path: urlPath}

	resp, err := doProbeRequest(ctx, client, http.MethodHead, u.String(), "")
	if err != nil {
		return probeResult{}, false
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		_ = resp.Body.Close()
		resp, err = doProbeRequest(ctx, client, http.MethodGet, u.String(), "bytes=0-0")
		if err != nil {
			return probeResult{}, false
		}
	}
	pr := probeResult{scheme: scheme, status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), reachable: true}
	_ = resp.Body.Close()
	return pr, true
}

// exposureProbeHTTPClient builds the pinned-dial client shared by the
// headers-only probe and the phpinfo body confirmation: connections dial the
// vhost's configured serving address (never DNS), SNI/Host carry the domain,
// and redirects are never followed. The returned func releases idle
// connections; a fresh transport per probe is needed because SNI
// (ServerName) is per-domain.
func exposureProbeHTTPClient(domain, host string) (*http.Client, func()) {
	transport := &http.Transport{
		MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &net.Dialer{Timeout: exposureProbeConnTimeout}
			return d.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		// #nosec G402 -- reachability probe to this host's own serving IP (never
		// an external endpoint); no trust decision rides on the certificate, and
		// SNI must match the requested domain to select the right vhost.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: domain},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   exposureProbeTotalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport.CloseIdleConnections
}

// phpinfoBodyReadMax bounds how much of the phpinfo.php response body the
// confirmation stage reads. Real dumps put "PHP Version" in the first couple
// of KB; 64 KiB leaves generous room for custom headers while keeping the
// probe cheap.
const phpinfoBodyReadMax = 64 << 10

// phpinfoMinBodyBytes is the minimum confirmed-dump size. Even a minimal PHP
// build renders tens of KB of phpinfo output; the observed false-positive
// stubs answer with empty or sub-100-byte bodies.
const phpinfoMinBodyBytes = 4096

// phpinfoBodyFetcher retrieves up to phpinfoBodyReadMax bytes of the response
// body for a phpinfo candidate. The bool reports whether the result can clear
// an earlier finding: non-success HTTP statuses are complete negatives, while
// transport, body-read, and inconclusive partial-response failures are not.
// This separate seam keeps every other exposure class on its headers-only
// contract.
type phpinfoBodyFetcher func(ctx context.Context, scheme, domain, host, urlPath string) ([]byte, bool)

var fetchPHPInfoBody phpinfoBodyFetcher = realFetchPHPInfoBody

func realFetchPHPInfoBody(ctx context.Context, scheme, domain, host, urlPath string) ([]byte, bool) {
	host = normalizeServingIP(host)
	if host == "" {
		return nil, false
	}
	fetchCtx, cancel := context.WithTimeout(ctx, exposureProbeTotalTimeout)
	defer cancel()
	client, closeIdle := exposureProbeHTTPClient(domain, host)
	defer closeIdle()
	u := url.URL{Scheme: scheme, Host: domain, Path: urlPath}
	return fetchPHPInfoBodyWithClient(fetchCtx, client, u.String())
}

func fetchPHPInfoBodyWithClient(ctx context.Context, client *http.Client, u string) ([]byte, bool) {
	resp, err := doProbeRequest(ctx, client, http.MethodGet, u, "")
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	partial := resp.StatusCode == http.StatusPartialContent
	if resp.StatusCode != http.StatusOK && !partial {
		return nil, true
	}
	reader := io.Reader(resp.Body)
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "":
	case "gzip":
		compressed, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, false
		}
		defer func() { _ = compressed.Close() }()
		reader = compressed
	default:
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(reader, phpinfoBodyReadMax))
	if err != nil {
		return nil, false
	}
	if partial && !isRealPHPInfoBody(body) {
		return nil, false
	}
	return body, true
}

// confirmPHPInfoBody checks both origin protocols because HEAD and GET can be
// routed differently, and HTTPS and HTTP can execute different handlers. A
// dump observed on either protocol is conclusive; if neither exposes a dump,
// every GET must complete before an earlier finding can be cleared.
func confirmPHPInfoBody(ctx context.Context, preferredScheme, domain, host, urlPath string) (string, bool, bool) {
	schemes := []string{"https", "http"}
	if preferredScheme == "http" {
		schemes[0], schemes[1] = schemes[1], schemes[0]
	}
	complete := true
	for _, scheme := range schemes {
		body, ok := fetchPHPInfoBody(ctx, scheme, domain, host, urlPath)
		if !ok {
			complete = false
			continue
		}
		if isRealPHPInfoBody(body) {
			return scheme, true, true
		}
	}
	return "", false, complete
}

// isRealPHPInfoBody reports whether a response body is genuine phpinfo()
// output: the version banner every phpinfo variant emits (HTML "PHP Version
// x.y" heading or CLI "PHP Version => x.y") plus a dump-sized body. UTF-16
// variants cover output handlers that transcode the otherwise ASCII banner.
func isRealPHPInfoBody(body []byte) bool {
	if len(body) < phpinfoMinBodyBytes {
		return false
	}
	marker := []byte("PHP Version")
	if bytes.Contains(body, marker) {
		return true
	}
	le := make([]byte, len(marker)*2)
	be := make([]byte, len(marker)*2)
	for i, b := range marker {
		le[i*2] = b
		be[i*2+1] = b
	}
	return bytes.Contains(body, le) || bytes.Contains(body, be)
}

func doProbeRequest(ctx context.Context, client *http.Client, method, u, rangeHdr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	req.Header.Set("User-Agent", "csm-exposure-probe")
	return client.Do(req)
}

// exposedClass labels a docroot file by the kind of exposure it represents
// when the web server serves it as a raw download. The zero value classNone
// means "not a sensitive file" and is never emitted.
type exposedClass int

const (
	classNone exposedClass = iota
	classConfigLeak
	classDBDump
	classBackupArchive
	classSourceBackup
	classPHPInfo
	// classSampleSQL is a plain SQL file with a sample-specific name under a
	// framework/vendor/downloaded-project directory. It is still served, but is
	// a Warning rather than a Critical database dump.
	classSampleSQL
)

// severity maps a class to its finding severity. Credential- and
// database-bearing exposures are Critical; a leaked source backup is High;
// a phpinfo dump is Warning (information disclosure only).
func (c exposedClass) severity() alert.Severity {
	switch c {
	case classConfigLeak, classDBDump, classBackupArchive:
		return alert.Critical
	case classSourceBackup:
		return alert.High
	default:
		return alert.Warning
	}
}

// findingName is the stable registry key / audit-log check name per class.
func (c exposedClass) findingName() string {
	switch c {
	case classConfigLeak:
		return "web_exposed_config_leak"
	case classDBDump:
		return "web_exposed_db_dump"
	case classBackupArchive:
		return "web_exposed_backup_archive"
	case classSourceBackup:
		return "web_exposed_source_backup"
	case classPHPInfo:
		return "web_exposed_phpinfo"
	case classSampleSQL:
		return "web_exposed_sample_sql"
	default:
		return ""
	}
}

// vhost is one cPanel virtual host: the domain the web server answers for and
// the docroot it serves. Parsed from /etc/userdatadomains, which -- unlike the
// /home/*/public_html glob -- covers addon and subdomain docroots too.
type vhost struct {
	domain  string
	user    string
	typ     string
	docroot string
	// ip is the vhost's serving address (from the ip:443/ip:80 columns). The
	// reachability probe dials this rather than 127.0.0.1: LiteSpeed returns
	// 403 to loopback-originated requests even for files it serves (HTTP 200)
	// to a real request on the public IP, so a loopback probe confirms nothing.
	ip string
}

// parseUserdataDomains parses the /etc/userdatadomains map. Each line is
// "<domain>: <user>==<reseller>==<type>==<maindomain>==<docroot>==...".
// Wildcard, comment, and short/malformed lines are skipped.
func parseUserdataDomains(content string) []vhost {
	vhosts, _ := parseUserdataDomainsChecked(content)
	return vhosts
}

func parseUserdataDomainsChecked(content string) ([]vhost, bool) {
	var out []vhost
	complete := true
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*:") || strings.HasPrefix(line, "*.") {
			continue
		}
		colon := strings.Index(line, ": ")
		if colon <= 0 {
			complete = false
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(line[:colon]))
		fields := strings.Split(line[colon+2:], "==")
		if !validProbeDomain(domain) || len(fields) < 5 {
			complete = false
			continue
		}
		docroot := filepath.Clean(strings.TrimSpace(fields[4]))
		user := strings.TrimSpace(fields[0])
		if !filepath.IsAbs(docroot) || docroot == string(filepath.Separator) || user == "" {
			complete = false
			continue
		}
		servingIP := parseServingIP(fields)
		if servingIP == "" {
			// Without a literal serving address the vhost cannot be probed
			// reliably. Keep the row so callers can preserve partial-scan state,
			// but do not treat this map as a complete scan input.
			complete = false
		}
		out = append(out, vhost{
			domain:  domain,
			user:    user,
			typ:     strings.TrimSpace(fields[2]),
			docroot: docroot,
			ip:      servingIP,
		})
	}
	return out, complete
}

// parseServingIP extracts the vhost's serving address from the ip:443 column
// (preferred) or the ip:80 column. Only literal unicast IP addresses are
// accepted so a malformed map can never turn the pinned origin probe into a
// DNS lookup or a connection to a non-serving address.
func parseServingIP(fields []string) string {
	bindings := []struct {
		field int
		port  string
	}{
		{field: 6, port: "443"},
		{field: 5, port: "80"},
	}
	for _, binding := range bindings {
		if binding.field >= len(fields) {
			continue
		}
		hp := strings.TrimSpace(fields[binding.field])
		if hp == "" {
			continue
		}
		if host, port, err := net.SplitHostPort(hp); err == nil {
			if port == binding.port {
				if ip := normalizeServingIP(host); ip != "" {
					return ip
				}
			}
			continue
		}
		// cPanel may render IPv6 bindings without brackets. SplitHostPort
		// rejects those, so split at the last colon and validate both parts.
		if idx := strings.LastIndexByte(hp, ':'); idx > 0 {
			if strings.TrimSpace(hp[idx+1:]) == binding.port {
				if ip := normalizeServingIP(hp[:idx]); ip != "" {
					return ip
				}
			}
		}
	}
	return ""
}

// normalizeServingIP returns a canonical literal unicast address. In
// particular, it rejects hostnames, unspecified/listener addresses, loopback,
// multicast, and link-local addresses, none of which identify the vhost's
// externally serving origin.
func normalizeServingIP(host string) string {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || !ip.IsGlobalUnicast() {
		return ""
	}
	return ip.String()
}

// probeHost is the literal serving address the reachability probe dials. An
// empty result means the vhost must be skipped and the scan marked incomplete;
// loopback is deliberately not a fallback because it produces false 403s on
// LiteSpeed.
func probeHost(vh vhost) string {
	return normalizeServingIP(vh.ip)
}

// validProbeDomain rejects URL authority syntax. Without this guard a corrupt
// map entry containing a port could make the privileged daemon probe an
// arbitrary service on the serving IP instead of the vhost's port 80/443.
func validProbeDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, ":/\\?#@[]%") {
		return false
	}
	for _, r := range domain {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// probeResult is the local reachability check outcome for one candidate file.
// It carries the requested scheme and only headers-level response facts
// (status, Content-Type); the body is never read, so a leaked file's secret
// contents never enter CSM.
type probeResult struct {
	scheme      string
	status      int
	contentType string
	reachable   bool
	// partial is true when one protocol could not be reached. Unless the other
	// protocol confirms an exposure, that uncertainty must prevent purging a
	// finding observed during an earlier complete scan.
	partial bool
}

// confirmExposure reports whether a classified candidate is a confirmed,
// downloadable exposure. It fails closed: anything the server blocks
// (403/404), redirects (3xx), or that comes back as executed HTML on a
// non-executing class is not a finding.
func confirmExposure(class exposedClass, pr probeResult) bool {
	if !pr.reachable {
		return false
	}
	if pr.status != 200 && pr.status != 206 {
		return false
	}
	if class == classPHPInfo {
		return true
	}
	// Non-executing sensitive files: a raw (non-HTML) body means the server
	// served the file itself. An HTML body means it executed or returned an
	// error/challenge page -- not a confirmed source leak.
	return !isHTMLContentType(pr.contentType)
}

func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/xhtml")
}

// phpExecExts are the extensions a cPanel PHP handler executes rather than
// serving as text. A backup whose FINAL extension is one of these is run by
// the interpreter, emits no source, and is therefore not a leak.
var phpExecExts = map[string]bool{
	"php": true, "php3": true, "php4": true, "php5": true, "php7": true,
	"php8": true, "phtml": true, "pht": true, "phar": true,
}

// backupSuffixSet are terminal dot-segments that mark a renamed backup a web
// server serves as text (not executed). "bak-<timestamp>" style segments are
// matched by prefix in isBackupSuffix.
var backupSuffixSet = map[string]bool{
	"old": true, "bak": true, "save": true, "orig": true, "broken": true,
	"swp": true, "swo": true, "tmp": true, "copy": true, "backup": true,
}

// dbDumpSuffixes are raw database-dump endings. Each may optionally be wrapped
// in one of dbDumpArchiveSuffixes.
var dbDumpSuffixes = []string{
	".sql", ".dump", ".mysql",
}

var dbDumpArchiveSuffixes = []string{
	"", ".gz", ".zip", ".bz2", ".xz", ".zst", ".7z", ".rar",
	".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tgz", ".tbz",
}

// archiveExts are archive endings that, combined with a backup token, denote a
// full-site backup a visitor could download whole.
var archiveExts = []string{
	".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".tar.zst", ".tar",
	".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst",
}

// backupTokens are name fragments that mark an archive as a site/db backup
// rather than a legitimately-offered download. Kept strong to avoid flagging
// ordinary user zips.
var backupTokens = []string{
	"public_html", "wp-content",
}

// These generic words are backup signals only as complete filename tokens;
// substring matching would turn names such as dumpster.zip or immigration.zip
// into Critical false positives.
var delimitedBackupTokens = []string{
	"backup", "dump", "full",
}

// sampleSQLDirMarkers are directory-name segments that provide supporting
// context for a sample-specific SQL file name. Directory context alone is not
// enough to demote a dump because these paths are customer-controlled.
var sampleSQLDirMarkers = map[string]bool{
	"example": true, "examples": true,
	"sample": true, "samples": true,
	"demo": true, "demos": true,
	"doc": true, "docs": true,
	"fixture": true, "fixtures": true, "testdata": true,
	"vendor": true, "node_modules": true, "bower_components": true,
}

var sampleSQLNameTokens = map[string]bool{
	"demo": true, "example": true, "fixture": true, "install": true,
	"migration": true, "sample": true, "schema": true, "seed": true,
	"setup": true, "structure": true, "update": true, "upgrade": true,
}

// isSampleSQLPath reports whether rel (a leading-slash URL path) names a plain
// SQL file with a sample/schema-specific name under framework scaffolding.
// Both the file name and directory context must support that classification.
// Archived, renamed, and customer-named dumps remain Critical even under a
// generic docs/vendor path.
func isSampleSQLPath(rel string) bool {
	segs := strings.Split(rel, "/")
	if len(segs) < 2 {
		return false
	}
	name := strings.ToLower(segs[len(segs)-1])
	if !strings.HasSuffix(name, ".sql") {
		return false
	}
	stem := strings.TrimSuffix(name, ".sql")
	sampleName := false
	for _, token := range strings.FieldsFunc(stem, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	}) {
		if sampleSQLNameTokens[token] {
			sampleName = true
			break
		}
	}

	archiveProject := false
	for _, seg := range segs[:len(segs)-1] { // dir segments only, skip file name
		s := strings.ToLower(seg)
		if s == "" {
			continue
		}
		if sampleName && sampleSQLDirMarkers[s] {
			return true
		}
		// Directories unpacked from a GitHub archive keep a "-master"/"-main"
		// suffix, a strong signal the tree is a downloaded sample project.
		if (strings.HasSuffix(s, "-master") && len(s) > len("-master")) ||
			(strings.HasSuffix(s, "-main") && len(s) > len("-main")) {
			archiveProject = true
		}
	}
	return archiveProject && (sampleName || stem == "database")
}

// demoteSampleSQL lowers a database-dump candidate to classSampleSQL when its
// path has specific sample-file and framework-scaffolding signals. Only
// classDBDump is eligible; credential, archive, and source classes are never
// demoted.
func demoteSampleSQL(class exposedClass, rel string) exposedClass {
	if class == classDBDump && isSampleSQLPath(rel) {
		return classSampleSQL
	}
	return class
}

// classifyExposedFile classifies a base file name. It is deliberately
// conservative: the benign long tail (samples, examples, live scripts, and
// backups that still execute) returns classNone so the detector does not
// drown operators in false positives.
func classifyExposedFile(name string) exposedClass {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return classNone
	}

	// Diagnostic by its unambiguous conventional name. A generic info.php can
	// be any application endpoint, and headers alone cannot prove it calls
	// phpinfo(), so classifying that name would create false positives.
	if lower == "phpinfo.php" {
		return classPHPInfo
	}

	// Benign long tail excluded before any leak matching.
	if isBenignExposedName(lower) {
		return classNone
	}

	// Live scripts are executed by the PHP handler rather than served as
	// source. Keep the phpinfo diagnostic exceptions above, but reject every
	// other candidate whose final extension still executes -- including names
	// such as .env.php that would otherwise match the dotenv family.
	if hasPHPExecExtension(lower) {
		return classNone
	}

	// Dotenv family (secrets), including editor backups such as .env~.
	if isDotenvName(lower) {
		return classConfigLeak
	}

	if hasDBDumpSuffix(lower) {
		return classDBDump
	}

	if isBackupArchive(lower) {
		return classBackupArchive
	}

	// A sensitive file can itself have been renamed with one or more backup
	// suffixes (for example wp-config.php.bak.old).
	if stripped, ok := stripBackupSuffixes(lower); ok {
		switch {
		case isDotenvName(stripped):
			return classConfigLeak
		case hasDBDumpSuffix(stripped):
			return classDBDump
		case isBackupArchive(stripped):
			return classBackupArchive
		case looksLikePHPSource(stripped):
			if looksLikeConfig(stripped) {
				return classConfigLeak
			}
			return classSourceBackup
		}
	}

	return classNone
}

func isDotenvName(lower string) bool {
	return lower == ".env" || strings.HasPrefix(lower, ".env.")
}

// isBenignExposedName matches shipped samples and templates that carry no
// secret and must never be flagged.
func isBenignExposedName(lower string) bool {
	if lower == "wp-config-sample.php" {
		return true
	}
	if stripped, ok := stripBackupSuffixes(lower); ok && stripped == "wp-config-sample.php" {
		return true
	}
	for _, template := range []string{".env.example", ".env.sample", ".env.dist", ".env.default"} {
		if lower == template || strings.HasPrefix(lower, template+".") || strings.HasPrefix(lower, template+"~") {
			return true
		}
	}
	return strings.HasSuffix(lower, ".dist") || strings.HasSuffix(lower, ".default")
}

func hasDBDumpSuffix(lower string) bool {
	for _, base := range dbDumpSuffixes {
		for _, archive := range dbDumpArchiveSuffixes {
			if strings.HasSuffix(lower, base+archive) {
				return true
			}
		}
	}
	return false
}

func isBackupArchive(lower string) bool {
	if strings.HasSuffix(lower, ".wpress") {
		return true
	}
	hasArchiveExt := false
	for _, e := range archiveExts {
		if strings.HasSuffix(lower, e) {
			hasArchiveExt = true
			break
		}
	}
	if !hasArchiveExt {
		return false
	}
	for _, tok := range backupTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	for _, tok := range delimitedBackupTokens {
		if hasDelimitedFilenameToken(lower, tok) {
			return true
		}
	}
	return false
}

func hasDelimitedFilenameToken(name, token string) bool {
	for start := 0; start <= len(name)-len(token); {
		i := strings.Index(name[start:], token)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isASCIIAlphaNumeric(name[i-1])
		after := i + len(token)
		afterOK := after == len(name) || !isASCIIAlphaNumeric(name[after])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
	return false
}

func isASCIIAlphaNumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// stripBackupSuffix removes a single trailing backup marker (a "~" or a
// terminal dot-segment such as ".old" / ".bak-20260515") and reports whether
// one was found.
func stripBackupSuffix(lower string) (string, bool) {
	if strings.HasSuffix(lower, "~") {
		return strings.TrimSuffix(lower, "~"), true
	}
	idx := strings.LastIndexByte(lower, '.')
	if idx <= 0 {
		return lower, false
	}
	seg := lower[idx+1:]
	if isBackupSuffix(seg) {
		return lower[:idx], true
	}
	return lower, false
}

func stripBackupSuffixes(lower string) (string, bool) {
	stripped := lower
	found := false
	for {
		next, ok := stripBackupSuffix(stripped)
		if !ok {
			return stripped, found
		}
		stripped = next
		found = true
	}
}

func isBackupSuffix(seg string) bool {
	if backupSuffixSet[seg] || isASCIIDigits(seg) {
		return true
	}
	// "bak-20260515-124446", "bak_1", "save1" style timestamped variants.
	for _, p := range []string{"bak-", "bak_", "old-", "old_", "save-", "save_", "backup-", "backup_", "orig-", "orig_"} {
		if strings.HasPrefix(seg, p) {
			return true
		}
	}
	for _, p := range []string{"bak", "old", "save", "backup", "orig"} {
		if strings.HasPrefix(seg, p) && isASCIIDigits(strings.TrimPrefix(seg, p)) {
			return true
		}
	}
	return false
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// looksLikePHPSource reports whether the name (with its backup suffix already
// removed) is a PHP source file the server would serve as text.
func looksLikePHPSource(stripped string) bool {
	return hasPHPExecExtension(stripped)
}

func hasPHPExecExtension(name string) bool {
	idx := strings.LastIndexByte(name, '.')
	if idx < 0 {
		return false
	}
	ext := name[idx+1:]
	return phpExecExts[ext]
}

// looksLikeConfig reports whether a source backup carries configuration /
// credentials, warranting Critical instead of High.
func looksLikeConfig(stripped string) bool {
	for _, tok := range []string{"config", "wp-config", "settings", "database", "db-config", "credentials", "secret"} {
		if strings.Contains(stripped, tok) {
			return true
		}
	}
	return false
}

package checks

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/wpcheck"
)

const (
	// webshellCallerLookback bounds how old a request may be. A quiet site's
	// log tail holds lines for days, and they must not keep a caller reported.
	webshellCallerLookback = 24 * time.Hour

	// webshellPublicClients is the number of distinct clients from which a
	// flagged file is read as a public page or an embedded URL rather than an
	// operated shell. Its clients are then not reported one by one.
	webshellPublicClients = 10
)

// webshellCallers collects, during one domlog pass, the clients that request
// a flagged file.
type webshellCallers struct {
	// docroots maps a vhost to its document root.
	docroots map[string]string
	flagged  map[string]bool
	// paths holds the hits per flagged file, then per client.
	paths map[string]*webshellPathHits
}

type webshellPathHits struct {
	clients map[webshellRequestSource]*webshellHits
}

type webshellRequestSource struct {
	client, domain, account string
}

type webshellHits struct {
	reportable      bool
	requests, posts int
	newest          time.Time
	sample          string
}

// loadWebshellCallers builds the collector for one domlog pass. It is nil,
// and costs the pass nothing, when no file is flagged or the host has no
// per-domain document root map.
func loadWebshellCallers(store *state.Store) *webshellCallers {
	if store == nil || !platform.Detect().IsCPanel() {
		return nil
	}
	var latest []alert.Finding
	for _, f := range store.LatestFindings() {
		if f.Severity == alert.Critical && malwareFileCheck(f.Check) {
			latest = append(latest, f)
		}
	}
	removed := RemovedFiles()
	if len(latest) == 0 && len(removed) == 0 {
		return nil
	}
	data, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return nil
	}
	vhosts, _ := parseUserdataDomainRootsChecked(string(data))
	docroots := make(map[string]string, len(vhosts))
	roots := make([]string, 0, len(vhosts))
	for _, vh := range vhosts {
		docroots[vh.domain] = vh.docroot
		roots = append(roots, vh.docroot)
	}
	flagged := webshellFlaggedFiles(latest, removed, roots)
	if flagged == nil {
		return nil
	}
	return &webshellCallers{docroots: docroots, flagged: flagged}
}

// File attribution needs the whole target. Other domlog consumers keep their
// existing retention limit even when this collector shares their scan.
func parseWebshellCallerRecord(line string) (accessLogRecord, bool) {
	rec, ok := parseAccessLogRecordWithURILimit(line, len(line))
	if len(rec.URI) > accessLogURILimit {
		rec.fullURI = rec.URI
		rec.URI = rec.URI[:accessLogURILimit]
	}
	return rec, ok
}

// record counts rec for client when it requests a flagged file.
func (w *webshellCallers) record(rec accessLogRecord, client string, now time.Time, reportable bool) {
	if w == nil || rec.Domain == "" || rec.Time.IsZero() || now.Sub(rec.Time) > webshellCallerLookback {
		return
	}
	docroot, ok := w.docroots[strings.ToLower(rec.Domain)]
	if !ok {
		return
	}
	uri := rec.URI
	if rec.fullURI != "" {
		uri = rec.fullURI
	}
	file, ok := requestedFile(docroot, uri, w.flagged)
	if !ok {
		return
	}
	if w.paths == nil {
		w.paths = make(map[string]*webshellPathHits)
	}
	hits := w.paths[file]
	if hits == nil {
		hits = &webshellPathHits{clients: make(map[webshellRequestSource]*webshellHits)}
		w.paths[file] = hits
	}
	source := webshellRequestSource{client: client, domain: strings.ToLower(rec.Domain), account: rec.Account}
	c := hits.clients[source]
	if c == nil {
		c = &webshellHits{}
		hits.clients[source] = c
	}
	c.reportable = c.reportable || reportable
	c.requests++
	if rec.Method == "POST" {
		c.posts++
	}
	if !rec.Time.Before(c.newest) {
		c.newest = rec.Time
		c.sample = rec.Method + " " + truncate(rec.URI, 200) + " " + itoa(rec.Status)
	}
}

// webshellCaller is one client's hits on one account.
type webshellCaller struct {
	client, account string
	domains         map[string]bool
	files           []string
	webshellHits
}

// emit returns one finding per client and account, and one per flagged file
// that too many clients request to be an operated shell.
func (w *webshellCallers) emit() []alert.Finding {
	if w == nil {
		return nil
	}
	files := make([]string, 0, len(w.paths))
	for file := range w.paths {
		files = append(files, file)
	}
	sort.Strings(files)

	var out []alert.Finding
	callers := make(map[string]*webshellCaller)
	var keys []string
	for _, file := range files {
		hits := w.paths[file]
		clients := make(map[string]bool)
		domains := make(map[string]bool)
		accounts := make(map[string]bool)
		for source := range hits.clients {
			clients[source.client] = true
			domains[source.domain] = true
			accounts[source.account] = true
		}
		if len(clients) >= webshellPublicClients {
			domain, account := "", ""
			if len(domains) == 1 {
				for d := range domains {
					domain = d
				}
			}
			if len(accounts) == 1 {
				for a := range accounts {
					account = a
				}
			}
			out = append(out, alert.Finding{
				Severity: alert.Warning,
				Check:    "webshell_path_public",
				TenantID: account,
				Domain:   domain,
				DedupKey: file,
				Message:  "Flagged PHP file requested by many clients: " + file,
				Details: itoa(len(clients)) + " clients requested it in the last 24 hours. The address is public or embedded in a page, " +
					"so its clients are not reported one by one.",
			})
			continue
		}
		label := file
		if w.flagged[file] {
			label += " (removed)"
		}
		for source, c := range hits.clients {
			if !c.reportable {
				continue
			}
			scope := source.account
			if scope == "" {
				scope = source.domain
			}
			key := source.client + "|" + scope
			caller := callers[key]
			if caller == nil {
				caller = &webshellCaller{client: source.client, account: source.account, domains: make(map[string]bool)}
				callers[key] = caller
				keys = append(keys, key)
			}
			caller.domains[source.domain] = true
			if len(caller.files) == 0 || caller.files[len(caller.files)-1] != label {
				caller.files = append(caller.files, label)
			}
			caller.requests += c.requests
			caller.posts += c.posts
			if c.newest.After(caller.newest) || (c.newest.Equal(caller.newest) && c.sample < caller.sample) {
				caller.newest, caller.sample = c.newest, c.sample
			}
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := callers[key]
		domain := ""
		if len(c.domains) == 1 {
			for d := range c.domains {
				domain = d
			}
		}
		scope := c.account
		if scope == "" {
			scope = domain
		}
		requests := itoa(c.requests) + " requests"
		if c.requests == 1 {
			requests = "1 request"
		}
		shown := c.files
		more := ""
		if len(shown) > 3 {
			more = "\nand " + itoa(len(shown)-3) + " more"
			shown = shown[:3]
		}
		out = append(out, alert.Finding{
			Severity: alert.High,
			Check:    "webshell_caller",
			SourceIP: c.client,
			TenantID: c.account,
			Domain:   domain,
			DedupKey: key,
			Message:  "Requests to a flagged PHP file from " + c.client + " on " + scope,
			Details: requests + " (" + itoa(c.posts) + " POST), newest " + c.newest.UTC().Format("2006-01-02 15:04:05 MST") +
				"\nFiles:\n" + strings.Join(shown, "\n") + more +
				"\nSample: " + c.sample,
		})
	}
	return out
}

// webshellFlaggedFiles returns the files whose requests name a webshell
// caller, keyed by path; the value is true when the path is flagged because
// CSM removed the file. A Critical content finding alone is not enough: it
// also covers a site's own pages with injected code, and their visitors are
// not callers. Nil when nothing is flagged.
func webshellFlaggedFiles(latest []alert.Finding, removed []RemovedFile, docroots []string) map[string]bool {
	roots := NewDocrootIndex(docroots)
	var flagged map[string]bool
	add := func(path string, removal bool) {
		if !filepath.IsAbs(path) {
			return
		}
		path = filepath.Clean(path)
		if _, ok := flagged[path]; ok || !webshellCallerTarget(path, roots) {
			return
		}
		if flagged == nil {
			flagged = make(map[string]bool)
		}
		flagged[path] = removal
	}
	for _, f := range latest {
		if f.Severity == alert.Critical && malwareFileCheck(f.Check) {
			add(f.FilePath, false)
		}
	}
	for _, r := range removed {
		// A cleaned file is the site's own and still served. A quarantined
		// path that holds a file again counts only through a new finding:
		// the site may have been rebuilt.
		if r.Action != "quarantine" {
			continue
		}
		if _, err := osFS.Lstat(r.Path); os.IsNotExist(err) {
			add(r.Path, true)
		}
	}
	return flagged
}

// webshellCallerTarget excludes known entry points from caller attribution.
// Other flagged PHP files can still be public or embedded in a page.
func webshellCallerTarget(path string, roots *DocrootIndex) bool {
	if !contenttype.IsExecutablePHPName(strings.ToLower(filepath.Base(path))) {
		return false
	}
	root := roots.Lookup(path)
	if root == "" || path == filepath.Join(root, "index.php") {
		return false
	}
	if shippedByRelease(path) {
		return false
	}
	// An entry file name proves nothing by itself: it is an entry point only
	// at the root of an install.
	dir := filepath.Dir(path)
	if wpcheck.DetectWPRoot(path) == dir {
		if _, err := osFS.Stat(filepath.Join(dir, "wp-includes", "version.php")); err == nil {
			return false
		}
	}
	return true
}

// requestedFile returns the flagged file a request for uri on the site at
// docroot runs. The request path is compared as the web server resolves it:
// decoded once, without its query, with a script's trailing path info cut and
// a directory answered by its index.
func requestedFile(docroot, uri string, flagged map[string]bool) (string, bool) {
	if len(flagged) == 0 || !strings.HasPrefix(uri, "/") {
		return "", false
	}
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	// Encoded slashes depend on the vhost's AllowEncodedSlashes policy.
	// Without that policy, decoding them could name a different file.
	if strings.Contains(strings.ToLower(uri), "%2f") {
		return "", false
	}
	decoded, err := url.PathUnescape(uri)
	if err != nil || strings.IndexByte(decoded, 0) >= 0 {
		return "", false
	}
	parts := strings.Split(decoded, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
		case "..":
			// Servers reject traversal above the URL root instead of clamping it.
			if len(clean) == 0 {
				return "", false
			}
			clean = clean[:len(clean)-1]
		default:
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "", false
	}
	file := docroot + "/" + strings.Join(clean, "/")
	end := len(docroot)
	for _, part := range clean {
		end += 1 + len(part)
		// A directory can carry a script's name, so every script-named
		// prefix is a candidate, not only the first.
		if contenttype.IsExecutablePHPName(strings.ToLower(part)) {
			candidate := file[:end]
			if _, ok := flagged[candidate]; ok {
				return candidate, true
			}
		}
	}
	last := parts[len(parts)-1]
	if last == "" || last == "." || last == ".." {
		file += "/index.php"
		if _, ok := flagged[file]; ok {
			return file, true
		}
	}
	return "", false
}

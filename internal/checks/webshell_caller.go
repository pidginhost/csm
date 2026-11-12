package checks

import (
	"net/url"
	"os"
	"path"
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
	domain, account string
	clients         map[string]*webshellHits
}

type webshellHits struct {
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

// record counts rec for client when it requests a flagged file.
func (w *webshellCallers) record(rec accessLogRecord, client string, now time.Time) {
	if w == nil || rec.Domain == "" || rec.Time.IsZero() || now.Sub(rec.Time) > webshellCallerLookback {
		return
	}
	docroot, ok := w.docroots[strings.ToLower(rec.Domain)]
	if !ok {
		return
	}
	file, ok := requestedFile(docroot, rec.URI, w.flagged)
	if !ok {
		return
	}
	if w.paths == nil {
		w.paths = make(map[string]*webshellPathHits)
	}
	hits := w.paths[file]
	if hits == nil {
		hits = &webshellPathHits{domain: rec.Domain, account: rec.Account, clients: make(map[string]*webshellHits)}
		w.paths[file] = hits
	}
	c := hits.clients[client]
	if c == nil {
		c = &webshellHits{}
		hits.clients[client] = c
	}
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
		if len(hits.clients) >= webshellPublicClients {
			out = append(out, alert.Finding{
				Severity: alert.Warning,
				Check:    "webshell_path_public",
				TenantID: hits.account,
				Domain:   hits.domain,
				DedupKey: file,
				Message:  "Flagged PHP file requested by many clients: " + file,
				Details: itoa(len(hits.clients)) + " clients requested it in the last 24 hours. The address is public or embedded in a page, " +
					"so its clients are not reported one by one.",
			})
			continue
		}
		label := file
		if w.flagged[file] {
			label += " (removed)"
		}
		for client, c := range hits.clients {
			scope := hits.account
			if scope == "" {
				scope = hits.domain
			}
			key := client + "|" + scope
			caller := callers[key]
			if caller == nil {
				caller = &webshellCaller{client: client, account: hits.account, domains: make(map[string]bool)}
				callers[key] = caller
				keys = append(keys, key)
			}
			caller.domains[hits.domain] = true
			caller.files = append(caller.files, label)
			caller.requests += c.requests
			caller.posts += c.posts
			if !c.newest.Before(caller.newest) {
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

// webshellCallerTarget reports whether a request for path runs a file that
// only its operator has a reason to request: PHP a web server executes, inside
// a document root, and not one of the site's entry points.
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
	decoded, err := url.PathUnescape(uri)
	if err != nil || strings.IndexByte(decoded, 0) >= 0 {
		return "", false
	}
	clean := path.Clean(decoded)
	if clean == "/" {
		return "", false
	}
	file := docroot
	for _, part := range strings.Split(clean[1:], "/") {
		file += "/" + part
		// A directory can carry a script's name, so every script-named
		// prefix is a candidate, not only the first.
		if contenttype.IsExecutablePHPName(strings.ToLower(part)) {
			if _, ok := flagged[file]; ok {
				return file, true
			}
		}
	}
	if strings.HasSuffix(decoded, "/") {
		file += "/index.php"
		if _, ok := flagged[file]; ok {
			return file, true
		}
	}
	return "", false
}

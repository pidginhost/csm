// Package updatecheck polls upstream release channels and tells the
// daemon whether a newer CSM version is available so the Web UI can
// surface a banner. It never fetches binaries or modifies the running
// install. Operators upgrade through their normal channel
// (apt, dnf, install.sh, deploy pipeline).
//
// Two sources, tried in order:
//
//  1. GitHub Releases API ("https://api.github.com/repos/pidginhost/csm/releases/latest").
//  2. apt-cache policy or dnf repoquery against the OS package, used
//     when the GitHub call fails (network blocked, rate-limited, etc.).
//
// The package never panics on a transient network or exec failure --
// it records the error in Info.Err and keeps the previous successful
// result in place so the banner does not flicker on a single bad poll.
package updatecheck

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"
)

// Info is the cached result surfaced to /api/v1/status. Zero value
// means "no check has completed yet"; CheckedAt.IsZero() is the
// canonical signal.
type Info struct {
	LatestVersion string    `json:"latest_version,omitempty"`
	Available     bool      `json:"available"`
	Source        string    `json:"source,omitempty"` // "github" | "apt" | "dnf"
	CheckedAt     time.Time `json:"checked_at,omitempty"`
	Err           string    `json:"err,omitempty"`
}

// PackageProbe queries the OS package manager for the highest
// available version of the configured package. Implementations
// must respect ctx for cancellation and timeout.
type PackageProbe func(ctx context.Context) (string, error)

// Options configures a Checker. Zero-valued fields take safe defaults.
type Options struct {
	// CurrentVersion is the running daemon's version string ("dev" is
	// treated as "always older than any tagged release").
	CurrentVersion string

	// Interval is how often the checker polls upstream. Clamped to a
	// minimum of 1h to avoid hammering the GitHub API.
	Interval time.Duration

	// GitHubAPIURL overrides the default GitHub releases URL. Used by
	// tests; production should leave this empty.
	GitHubAPIURL string

	// HTTPClient is the HTTP client used for the GitHub request. nil
	// gets a sane default with a 15s timeout.
	HTTPClient *http.Client

	// PackageProbe is the apt/dnf fallback. nil disables fallback.
	PackageProbe PackageProbe

	// Now lets tests inject a clock. Defaults to time.Now.
	Now func() time.Time

	// LogErr receives non-fatal probe errors. Optional; nil silences.
	LogErr func(source string, err error)
}

// Checker holds polling state. Safe for concurrent reads of Latest()
// while the goroutine started by Run is updating the cache.
type Checker struct {
	opts  Options
	cache atomic.Pointer[Info]
}

// New builds a Checker. Validate the options here so Run can rely on
// invariants without re-checking each tick.
func New(opts Options) *Checker {
	if opts.Interval <= 0 {
		opts.Interval = 24 * time.Hour
	}
	if opts.Interval < time.Hour {
		opts.Interval = time.Hour
	}
	if opts.GitHubAPIURL == "" {
		opts.GitHubAPIURL = defaultGitHubReleasesURL
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &Checker{opts: opts}
	c.cache.Store(&Info{})
	return c
}

// Latest returns the most recent successful poll plus any error from
// the most recent attempt. The returned value is safe to mutate.
func (c *Checker) Latest() Info {
	if v := c.cache.Load(); v != nil {
		return *v
	}
	return Info{}
}

// CheckOnce runs a single poll synchronously and returns the result.
// Run uses this internally; tests call it directly to avoid the ticker.
func (c *Checker) CheckOnce(ctx context.Context) Info {
	now := c.opts.Now()

	latest, err := fetchGitHubLatest(ctx, c.opts.HTTPClient, c.opts.GitHubAPIURL)
	source := "github"

	if err != nil {
		if c.opts.LogErr != nil {
			c.opts.LogErr("github", err)
		}
		if c.opts.PackageProbe != nil {
			pkgVer, pkgErr := c.opts.PackageProbe(ctx)
			if pkgErr == nil {
				latest = pkgVer
				source = pkgSourceLabel(c.opts.PackageProbe)
				err = nil
			} else {
				if c.opts.LogErr != nil {
					c.opts.LogErr("package", pkgErr)
				}
				err = pkgErr
			}
		}
	}

	info := Info{CheckedAt: now}
	if err != nil {
		// Preserve the last good LatestVersion so the banner does
		// not flicker on a single bad poll.
		prev := c.Latest()
		info.LatestVersion = prev.LatestVersion
		info.Available = prev.Available
		info.Source = prev.Source
		info.Err = err.Error()
	} else {
		info.LatestVersion = latest
		info.Source = source
		info.Available = isNewer(latest, c.opts.CurrentVersion)
	}

	c.cache.Store(&info)
	return info
}

// Run polls on the configured interval until ctx is cancelled. It
// performs an initial check after a 5-minute warm-up so daemon
// startup is not blocked on outbound HTTP.
func (c *Checker) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}

	c.CheckOnce(ctx)

	t := time.NewTicker(c.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CheckOnce(ctx)
		}
	}
}

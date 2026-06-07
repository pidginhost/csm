// Package adapter renders and applies the MTA-native forward-guard rule. On
// cPanel/exim it writes a router + transport into the cPanel-preserved
// /etc/exim.conf.local include sections and regenerates exim.conf via
// buildeximconf, so the rule survives cPanel exim rebuilds. CSM is never in the
// live mail path: exim evaluates the rule and writes held copies to the
// CSM-owned quarantine Maildir itself.
//
// The exact router/transport here was validated on a real cPanel exim 4.99
// host (null-sender forward held while the local copy delivers; normal mail
// forwarded unchanged; Remove restores normal forwarding).
package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

// Status reports whether the guard rule is currently installed.
type Status struct {
	Installed bool `json:"installed"`
}

// ForwardGuard renders and (un)installs the MTA forward-guard rule.
type ForwardGuard interface {
	Apply(cfg policy.Config, badIPs []string) error
	Remove() error
	Status() (Status, error)
}

// Default on-disk locations (overridable in tests).
const (
	defaultLocalConf     = "/etc/exim.conf.local"
	defaultBadIPsPath    = "/var/lib/csm/forward_guard/bad_ips"
	defaultQuarantineDir = "/var/lib/csm/forward_quarantine/held"
	// transportUser delivers held copies. It must NOT be root: cPanel lists
	// root on exim's never_users, so an appendfile as root fails. mailnull is
	// exim's own non-root identity and exists on every cPanel host.
	transportUser = "mailnull"
)

// Managed-block sentinels. Apply replaces whatever is between them, so a
// re-apply is idempotent and Remove can strip the block cleanly.
const (
	routerBegin    = "# CSM-FORWARD-GUARD ROUTER BEGIN (managed by csm; do not edit)"
	routerEnd      = "# CSM-FORWARD-GUARD ROUTER END"
	transportBegin = "# CSM-FORWARD-GUARD TRANSPORT BEGIN (managed by csm; do not edit)"
	transportEnd   = "# CSM-FORWARD-GUARD TRANSPORT END"
)

// eximLocalSkeleton is the full set of cPanel exim.conf.local section markers,
// created when the host has no exim.conf.local yet. cPanel's buildeximconf
// injects whatever follows each marker into the generated exim.conf.
const eximLocalSkeleton = `@AUTH@

@BEGINACL@

@CONFIG@

@DIRECTOREND@

@DIRECTORMIDDLE@

@DIRECTORSTART@

@ENDACL@

@RETRYEND@

@RETRYSTART@

@REWRITE@

@ROUTEREND@

@ROUTERSTART@

@TRANSPORTEND@

@TRANSPORTMIDDLE@

@TRANSPORTSTART@
`

// EximAdapter is the cPanel/exim ForwardGuard.
type EximAdapter struct {
	localConf     string
	badIPsPath    string
	quarantineDir string

	// Injected side effects (real implementations on a live host; fakes in tests).
	rebuild  func() error                  // runs buildeximconf
	chown    func(path, user string) error // chowns the quarantine dir
	mkdirAll func(path string, perm os.FileMode) error
}

// NewEximAdapter returns an adapter targeting the standard cPanel locations.
func NewEximAdapter() *EximAdapter {
	return &EximAdapter{
		localConf:     defaultLocalConf,
		badIPsPath:    defaultBadIPsPath,
		quarantineDir: defaultQuarantineDir,
		rebuild:       runBuildEximConf,
		chown:         chownToUser,
		mkdirAll:      os.MkdirAll,
	}
}

// Apply installs (or refreshes) the forward-guard rule for an enabled,
// non-dry-run policy. It is transactional: on any failure the previous
// exim.conf.local is restored and exim is rebuilt back to its prior state, so a
// failed apply never leaves a half-installed rule.
func (a *EximAdapter) Apply(cfg policy.Config, badIPs []string) error {
	if !cfg.Enabled {
		return fmt.Errorf("forward-guard adapter: cannot apply disabled policy")
	}
	if cfg.DryRun {
		return fmt.Errorf("forward-guard adapter: cannot apply dry-run policy")
	}

	router, err := a.renderRouter(cfg.HoldSignals)
	if err != nil {
		return err
	}

	prev, hadPrev, err := a.readLocalConf()
	if err != nil {
		return err
	}

	base := prev
	if !hadPrev || strings.TrimSpace(base) == "" {
		base = eximLocalSkeleton
	}
	next, err := injectBlock(base, "@ROUTERSTART@", router)
	if err != nil {
		return err
	}
	next, err = injectBlock(next, "@TRANSPORTSTART@", a.renderTransport())
	if err != nil {
		return err
	}

	// Quarantine dir must exist and be writable by the transport user before
	// exim can deliver into it.
	if err := a.mkdirAll(a.quarantineDir, 0700); err != nil {
		return fmt.Errorf("creating quarantine dir: %w", err)
	}
	if err := a.chown(a.quarantineDir, transportUser); err != nil {
		return fmt.Errorf("chowning quarantine dir to %s: %w", transportUser, err)
	}
	if err := a.writeBadIPs(badIPs); err != nil {
		return err
	}

	if err := writeFileAtomic(a.localConf, []byte(next)); err != nil {
		return err
	}
	if err := a.rebuild(); err != nil {
		// Roll back to the prior config so mail keeps flowing as before.
		if restoreErr := a.restore(prev, hadPrev); restoreErr != nil {
			return fmt.Errorf("buildeximconf failed: %w; rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("buildeximconf failed, rolled back: %w", err)
	}
	return nil
}

// Remove strips the managed blocks and rebuilds, restoring normal forwarding.
func (a *EximAdapter) Remove() error {
	cur, had, err := a.readLocalConf()
	if err != nil {
		return err
	}
	if !had {
		return nil // nothing installed
	}
	stripped := stripBlock(cur, routerBegin, routerEnd)
	stripped = stripBlock(stripped, transportBegin, transportEnd)
	if stripped == cur {
		return nil // not installed; no rebuild needed
	}
	if err := writeFileAtomic(a.localConf, []byte(stripped)); err != nil {
		return err
	}
	if err := a.rebuild(); err != nil {
		if restoreErr := a.restore(cur, true); restoreErr != nil {
			return fmt.Errorf("buildeximconf failed during remove: %w; rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("buildeximconf failed during remove, rolled back: %w", err)
	}
	return nil
}

// Status reports whether both managed blocks are present.
func (a *EximAdapter) Status() (Status, error) {
	cur, had, err := a.readLocalConf()
	if err != nil {
		return Status{}, err
	}
	if !had {
		return Status{}, nil
	}
	routerInstalled := strings.Contains(cur, routerBegin)
	transportInstalled := strings.Contains(cur, transportBegin)
	if routerInstalled != transportInstalled {
		return Status{}, fmt.Errorf("forward-guard adapter: partial install in exim.conf.local (router=%t transport=%t)", routerInstalled, transportInstalled)
	}
	return Status{Installed: routerInstalled}, nil
}

func (a *EximAdapter) renderRouter(sig policy.HoldSignals) (string, error) {
	var clauses []string
	if sig.BounceBackscatter {
		clauses = append(clauses, "{eq{$sender_address}{}}")
	}
	if sig.BadSenderIP {
		clauses = append(clauses, fmt.Sprintf("{eq{${lookup{$sender_host_address}lsearch{%s}{1}{0}}}{1}}", a.badIPsPath))
	}
	if len(clauses) == 0 {
		// Config validation forbids enforce mode with neither signal; guard here
		// so the adapter never installs a router that holds everything or nothing.
		return "", fmt.Errorf("forward-guard adapter: no routing-time-enforceable signal enabled (need bounce_backscatter or bad_sender_ip)")
	}
	cond := fmt.Sprintf("${if and{ {def:parent_local_part} {or{ %s } } }{yes}{no}}", strings.Join(clauses, " "))
	return strings.Join([]string{
		routerBegin,
		"csm_forward_guard:",
		"  driver = accept",
		"  domains = ! +local_domains",
		"  condition = " + cond,
		"  transport = csm_forward_hold",
		routerEnd,
	}, "\n"), nil
}

func (a *EximAdapter) renderTransport() string {
	headers := strings.Join([]string{
		"X-CSM-Forwarder: $parent_local_part@$parent_domain",
		"X-CSM-Recipient: $local_part@$domain",
		"X-CSM-Sender: $sender_address",
		"X-CSM-Reasons: ${if eq{$sender_address}{}{bounce_backscatter}{bad_sender_ip}}",
	}, "\\n")
	return strings.Join([]string{
		transportBegin,
		"csm_forward_hold:",
		"  driver = appendfile",
		"  directory = " + a.quarantineDir,
		"  maildir_format",
		"  create_directory",
		"  directory_mode = 0700",
		"  mode = 0600",
		"  user = " + transportUser,
		`  headers_add = "` + headers + `"`,
		transportEnd,
	}, "\n")
}

func (a *EximAdapter) writeBadIPs(ips []string) error {
	if err := a.mkdirAll(filepath.Dir(a.badIPsPath), 0755); err != nil {
		return fmt.Errorf("creating bad IP lookup dir: %w", err)
	}

	var buf bytes.Buffer
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || strings.ContainsAny(ip, " \t\r\n:") {
			continue // lsearch keys are one bare token per line
		}
		fmt.Fprintf(&buf, "%s: 1\n", ip)
	}
	return writeFileAtomic(a.badIPsPath, buf.Bytes())
}

func (a *EximAdapter) readLocalConf() (string, bool, error) {
	data, err := os.ReadFile(a.localConf) // #nosec G304 -- operator-fixed exim.conf.local path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading %s: %w", a.localConf, err)
	}
	return string(data), true, nil
}

func (a *EximAdapter) restore(prev string, had bool) error {
	if had {
		if err := writeFileAtomic(a.localConf, []byte(prev)); err != nil {
			return fmt.Errorf("restoring exim.conf.local: %w", err)
		}
	} else {
		if err := os.Remove(a.localConf); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing new exim.conf.local: %w", err)
		}
	}
	if err := a.rebuild(); err != nil {
		return fmt.Errorf("rebuilding restored exim config: %w", err)
	}
	return nil
}

// injectBlock removes any existing managed block of the same kind, then inserts
// block immediately after the marker line. Idempotent: re-injecting yields the
// same file.
func injectBlock(conf, marker, block string) (string, error) {
	// Strip a prior copy of this block so re-apply doesn't duplicate it.
	begin, end := blockSentinels(block)
	conf = stripBlock(conf, begin, end)

	markerLine := marker + "\n"
	idx := strings.Index(conf, markerLine)
	if idx < 0 {
		return "", fmt.Errorf("exim.conf.local missing %s marker", marker)
	}
	at := idx + len(markerLine)
	return conf[:at] + block + "\n" + conf[at:], nil
}

var blockSentinelRe = regexp.MustCompile(`^(# CSM-FORWARD-GUARD \w+ BEGIN)`)

func blockSentinels(block string) (begin, end string) {
	lines := strings.SplitN(block, "\n", 2)
	begin = lines[0]
	// Derive the END sentinel from the BEGIN kind.
	if m := blockSentinelRe.FindStringSubmatch(begin); m != nil {
		kind := strings.Fields(m[1])[2] // ROUTER or TRANSPORT
		return begin, "# CSM-FORWARD-GUARD " + kind + " END"
	}
	return begin, ""
}

// stripBlock removes the inclusive begin..end region (and a trailing newline).
func stripBlock(conf, begin, end string) string {
	for {
		bi := strings.Index(conf, begin)
		if bi < 0 {
			return conf
		}
		ei := strings.Index(conf[bi:], end)
		if ei < 0 {
			return conf
		}
		stop := bi + ei + len(end)
		if stop < len(conf) && conf[stop] == '\n' {
			stop++
		}
		conf = conf[:bi] + conf[stop:]
	}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.csmtmp") // #nosec G304 -- caller owns the destination path
	if err != nil {
		return fmt.Errorf("opening temp file for %s: %w", path, err)
	}
	tmp := f.Name()
	if err := f.Chmod(0644); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod temp file for %s: %w", path, err)
	}
	if n, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", path, err)
	} else if n != len(data) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", path, io.ErrShortWrite)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("committing %s: %w", path, err)
	}
	return nil
}

func runBuildEximConf() error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/scripts/buildeximconf").Run()
}

func chownToUser(path, user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "chown", "-R", user+":"+user, path).Run()
}

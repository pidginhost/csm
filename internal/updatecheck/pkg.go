package updatecheck

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

// AptProbe queries `apt-cache policy <pkg>` and returns the candidate
// version. Returns an error when apt-cache is missing, the package is
// unknown, or the candidate is "(none)".
func AptProbe(packageName string) PackageProbe {
	return func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "apt-cache", "policy", packageName) // #nosec G204 -- packageName is operator-controlled config, not attacker input
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("apt-cache policy: %w", err)
		}
		return parseAptPolicy(string(out))
	}
}

// DnfProbe queries `dnf --quiet repoquery --queryformat=%{version}
// <pkg>` and returns the highest version line. Returns an error when
// dnf is missing or returns no rows.
func DnfProbe(packageName string) PackageProbe {
	return func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "dnf", "--quiet", "repoquery", "--queryformat=%{version}\n", packageName) // #nosec G204 -- packageName is operator-controlled config, not attacker input
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("dnf repoquery: %w", err)
		}
		return parseDnfRepoquery(string(out))
	}
}

func parseAptPolicy(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Candidate:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
		if v == "" || v == "(none)" {
			return "", errors.New("apt-cache policy: candidate (none)")
		}
		return aptStripEpochRevision(v), nil
	}
	return "", errors.New("apt-cache policy: no candidate line")
}

func parseDnfRepoquery(out string) (string, error) {
	versions := []string{}
	for _, line := range strings.Split(out, "\n") {
		v := strings.TrimSpace(line)
		if v == "" {
			continue
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return "", errors.New("dnf repoquery: no versions")
	}
	sort.Slice(versions, func(i, j int) bool { return isNewer(versions[i], versions[j]) })
	return versions[0], nil
}

// aptStripEpochRevision drops the optional "EPOCH:" prefix and
// "-DEBIAN_REVISION" suffix added by the apt versioning scheme so the
// returned string can be compared to a plain semver tag.
func aptStripEpochRevision(v string) string {
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		v = v[:i]
	}
	return v
}

// pkgSourceLabel best-effort labels a probe as "apt" or "dnf" by name.
// Unknown probes get "package".
func pkgSourceLabel(p PackageProbe) string {
	if p == nil {
		return "package"
	}
	name := runtime.FuncForPC(reflect.ValueOf(p).Pointer()).Name()
	switch {
	case strings.Contains(name, "AptProbe"):
		return "apt"
	case strings.Contains(name, "DnfProbe"):
		return "dnf"
	default:
		return "package"
	}
}

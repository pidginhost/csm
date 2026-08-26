package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	cagefsMountPointsPath = "/etc/cagefs/cagefs.mp"
	cagefsRunCommand      = func(name string, args ...string) error {
		// #nosec G204 -- callers pass only the fixed cagefsctl command and literal arguments.
		return exec.Command(name, args...).Run()
	}
)

// ensurePHPShieldRuntimePaths prepares everything the Shield needs to record an
// event: the drop directory and log on the host, and the mount that makes them
// reachable from inside a CageFS cage.
//
// A cage that will not remount degrades logging but leaves the Shield itself
// working, so it warns rather than aborting an install half-way. The warning
// goes to the operator running the install, which is the whole point -- the
// previous failure mode only ever showed up in a customer's PHP error log.
func ensurePHPShieldRuntimePaths() error {
	if err := ensurePHPShieldEventLog(); err != nil {
		return err
	}
	if err := ensurePHPShieldCageFSMount(); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: PHP Shield events will not be recorded inside CageFS: %v\n", err)
	}
	return nil
}

// ensurePHPShieldCageFSMount exposes the Shield event directory inside every
// CageFS cage.
//
// PHP runs inside the cage, where /var/log holds only the cage skeleton. Without
// a mount entry the event directory does not exist there at all, so the Shield
// cannot append and every runtime detection is dropped with "cannot write to
// /var/log/csm-php-shield" in the customer's error log. The directory keeps its
// sticky write-only mode, so tenants can append events without reading them.
//
// A missing mount-points file means CageFS is not installed, which covers every
// non-CloudLinux host. An entry the operator already wrote is left alone
// whatever its prefix -- read-only ("!") or per-user ("@") is a deliberate
// choice, and appending a second, conflicting line for the same path is worse
// than logging nothing.
func ensurePHPShieldCageFSMount() error {
	// #nosec G304 -- fixed CageFS configuration path, overridden only in tests.
	data, err := os.ReadFile(cagefsMountPointsPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading CageFS mount points: %w", err)
	}
	if cagefsMountsPath(string(data), phpShieldEventDir) {
		return nil
	}

	entry := phpShieldEventDir + "\n"
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		entry = "\n" + entry
	}
	// #nosec G304 -- fixed CageFS configuration path, overridden only in tests.
	f, err := os.OpenFile(cagefsMountPointsPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening CageFS mount points: %w", err)
	}
	if _, err := f.WriteString(entry); err != nil {
		_ = f.Close()
		return fmt.Errorf("adding PHP Shield event dir to CageFS mount points: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing CageFS mount points: %w", err)
	}

	// Live cages keep their current mounts until they are rebuilt, so a fresh
	// entry alone leaves the running PHP pools blind.
	if err := cagefsRunCommand("cagefsctl", "--remount-all"); err != nil {
		return fmt.Errorf("remounting CageFS: %w", err)
	}
	return nil
}

// cagefsMountsPath reports whether the mount-points file already has an entry
// for dir under any of the prefixes CageFS accepts: a plain shared mount, "!"
// read-only, "@" per-user (which carries a trailing ",<mode>"), or "*".
func cagefsMountsPath(contents, dir string) bool {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "!@*")
		if path, _, found := strings.Cut(line, ","); found {
			line = path
		}
		if line == dir {
			return true
		}
	}
	return false
}

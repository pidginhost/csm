package platform

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PHPRuntimeUsers maps the UIDs PHP or CGI can run as to their source. An
// incomplete inspection must not be treated as proof of isolated workers.
func PHPRuntimeUsers() (map[uint32]string, error) { return phpRuntimeUsers("/") }

// The PHP command-line binary is not a web worker.
var phpWorkerName = regexp.MustCompile(`^(php-cgi|php-fpm|lsphp)[0-9.]*$|^fcgiwrap$`)

func phpRuntimeUsers(root string) (map[uint32]string, error) {
	out := map[uint32]string{}
	addUID := func(uid uint32, source string) {
		if out[uid] == "" {
			out[uid] = source
		}
	}
	lookup, err := phpUserLookup(root)
	if err != nil {
		return out, err
	}
	add := func(name, source string) error {
		uid, lookupErr := lookup(name)
		if lookupErr != nil {
			return lookupErr
		}
		addUID(uid, source)
		return nil
	}
	pools, err := phpFPMPools(root)
	if err != nil {
		return out, err
	}
	for _, pool := range pools {
		if err := add(pool.user, "PHP-FPM pool "+pool.name); err != nil {
			return out, err
		}
	}
	if err := phpProcessUsers(root, addUID, add); err != nil {
		return out, err
	}
	if err := apacheRuntimeUsers(root, add); err != nil {
		return out, err
	}
	if err := litespeedRuntimeUsers(root, add); err != nil {
		return out, err
	}
	return out, nil
}

// Use NSS on the live host, just as the firewall does. A fixture root has
// its own passwd database, so tests never depend on the host's accounts.
func phpUserLookup(root string) (func(string) (uint32, error), error) {
	names := map[string]string{}
	if root != "/" {
		data, err := os.ReadFile(filepath.Join(root, "etc/passwd")) // #nosec G304 -- root is an internal fixture directory; live lookups use NSS.
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) >= 3 {
				names[fields[0]] = fields[2]
			}
		}
	}
	return func(name string) (uint32, error) {
		if n, err := strconv.ParseUint(strings.TrimPrefix(name, "#"), 10, 32); err == nil {
			return uint32(n), nil
		}
		id := names[name]
		if root == "/" {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, fmt.Errorf("cannot resolve a PHP/CGI user: %w", err)
			}
			id = u.Uid
		}
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return 0, errors.New("cannot resolve a PHP/CGI user")
		}
		return uint32(n), nil
	}, nil
}

func phpProcessUsers(root string, add func(uint32, string), addName func(string, string) error) error {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return fmt.Errorf("inspect PHP/CGI processes: %w", err)
	}
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil || !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, "proc", entry.Name())
		exe, exeErr := os.Readlink(filepath.Join(dir, "exe"))
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		if exeErr != nil {
			comm, err := os.ReadFile(filepath.Join(dir, "comm")) // #nosec G304 -- dir is procfs plus a validated numeric PID.
			if os.IsNotExist(err) {
				continue // The process exited during the walk.
			}
			if err != nil {
				return fmt.Errorf("inspect process name: %w", err)
			}
			base = strings.TrimSpace(string(comm))
			if !phpWorkerName.MatchString(base) && !os.IsNotExist(exeErr) {
				return fmt.Errorf("inspect process executable: %w", exeErr)
			}
		}
		if liteSpeedServerName.MatchString(base) {
			if exeErr != nil {
				return fmt.Errorf("inspect LiteSpeed executable: %w", exeErr)
			}
			exe = strings.TrimSuffix(exe, " (deleted)")
			if !filepath.IsAbs(exe) || filepath.Base(filepath.Dir(exe)) != "bin" {
				return errors.New("cannot locate LiteSpeed server configuration")
			}
			conf := filepath.Join(root, filepath.Dir(filepath.Dir(exe)), "conf")
			if err := liteSpeedConfigUsers(conf, addName); err != nil {
				return err
			}
		}
		if !phpWorkerName.MatchString(base) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "status")) // #nosec G304 -- dir is procfs plus a validated numeric PID.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect PHP/CGI credentials: %w", err)
		}
		ids, err := procWorkerUIDs(string(data))
		if err != nil {
			return err
		}
		if ids[0] == 0 && ids[1] == 0 && strings.HasPrefix(base, "php-fpm") {
			cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")) // #nosec G304 -- dir is procfs plus a validated numeric PID.
			// Only a positively identified FPM supervisor is exempt. Root
			// CGI workers and FPM pools can serve requests themselves.
			if err == nil && strings.HasPrefix(string(cmd), "php-fpm: master process (") {
				continue
			}
		}
		for _, uid := range ids {
			add(uid, "a running "+base+" process")
		}
	}
	return nil
}

func procWorkerUIDs(status string) ([2]uint32, error) {
	var out [2]uint32
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) != 4 {
				break
			}
			// Sockets use the filesystem UID; also retain the effective UID
			// a worker can restore before opening a connection.
			for i, field := range []string{fields[1], fields[3]} {
				n, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return out, errors.New("invalid PHP/CGI process credentials")
				}
				out[i] = uint32(n)
			}
			return out, nil
		}
	}
	return out, errors.New("missing PHP/CGI process credentials")
}

// filepath.Glob suppresses I/O errors, which cannot establish that no pool
// is present. Walk each pattern component and preserve those errors.
func runtimeConfigGlob(pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		_, err := os.Stat(pattern) // #nosec G703 -- configured server includes may intentionally name files anywhere on the host.
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return []string{pattern}, nil
	}
	dirs, err := runtimeConfigGlob(filepath.Dir(pattern))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			ok, err := filepath.Match(filepath.Base(pattern), entry.Name())
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return out, nil
}

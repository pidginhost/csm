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
	"syscall"
)

// PHPRuntimeUsers maps the UIDs PHP or CGI can run as to their source. An
// incomplete inspection must not be treated as proof of isolated workers.
func PHPRuntimeUsers() (map[uint32]string, error) { return phpRuntimeUsers("/") }

// The PHP command-line binary is not a web worker.
var phpWorkerName = regexp.MustCompile(`^(php-cgi|php-fpm|lsphp)[0-9.]*$|^fcgiwrap$`)

type phpExecutableCheck func(string, phpProcessFiles, string) bool

func phpRuntimeUsers(root string) (map[uint32]string, error) {
	return inspectPHPRuntimeUsers(root, phpExecutableTrusted)
}

func inspectPHPRuntimeUsers(root string, trusted phpExecutableCheck) (map[uint32]string, error) {
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
	if err := phpProcessUsers(root, addUID, add, trusted); err != nil {
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

func phpProcessUsers(root string, add func(uint32, string), addName func(string, string) error, trusted phpExecutableCheck) error {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return fmt.Errorf("inspect PHP/CGI processes: %w", err)
	}
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil || !entry.IsDir() {
			continue
		}
		// An open proc directory remains tied to this process even if its
		// numeric PID is reused before the next credential or executable read.
		proc, err := os.OpenRoot(filepath.Join(root, "proc", entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect process directory: %w", err)
		}
		err = phpProcessUser(root, proc, add, addName, trusted)
		_ = proc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type phpProcessFiles interface {
	Open(string) (*os.File, error)
	Readlink(string) (string, error)
	ReadFile(string) ([]byte, error)
}

func phpProcessUser(root string, proc phpProcessFiles, add func(uint32, string), addName func(string, string) error, trusted phpExecutableCheck) error {
	exe, exeErr := proc.Readlink("exe")
	if errors.Is(exeErr, syscall.ESRCH) {
		return nil
	}
	data, err := proc.ReadFile("status")
	if procProcessExited(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect PHP/CGI process credentials: %w", err)
	}
	uid, uidErr := procRealUID(string(data))
	if uidErr != nil {
		return uidErr
	}
	ids, err := procWorkerUIDs(string(data))
	if err != nil {
		return err
	}
	if os.IsNotExist(exeErr) {
		stat, statErr := proc.ReadFile("stat")
		if procProcessExited(statErr) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect process liveness: %w", statErr)
		}
		inactive, stateErr := procNoUserspace(string(stat))
		if stateErr != nil {
			return stateErr
		}
		if inactive {
			return nil
		}
	}
	base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	worker := exeErr == nil && phpWorkerName.MatchString(base)
	identified := exeErr == nil && trusted(root, proc, exe)
	if !identified {
		if uid == 0 && !worker {
			// Root processes are the operator's, and package upgrades leave
			// them running replaced executables. Only an unreadable one, or
			// a LiteSpeed server whose configuration would come from it,
			// stops the inspection.
			if exeErr == nil && !liteSpeedServerName.MatchString(base) {
				return nil
			}
			return errors.New("cannot establish trusted process executable provenance")
		}
		source := "a running process whose executable cannot be verified"
		if worker {
			source = "a running " + base + " process"
		}
		for _, id := range ids {
			add(id, source)
		}
		return nil
	}
	if !worker {
		// Only a root-started server with an operator-controlled executable
		// can locate configuration. User copies have already been counted.
		if uid != 0 || !liteSpeedServerName.MatchString(base) {
			return nil
		}
		if filepath.Base(filepath.Dir(exe)) != "bin" {
			return errors.New("cannot locate LiteSpeed server configuration")
		}
		conf := filepath.Join(root, filepath.Dir(filepath.Dir(exe)), "conf")
		return liteSpeedConfigUsers(conf, addName)
	}
	if uid == 0 && ids[0] == 0 && ids[1] == 0 && strings.HasPrefix(base, "php-fpm") {
		cmd, cmdErr := proc.ReadFile("cmdline")
		// A title exempts only a trusted root-started FPM supervisor.
		if cmdErr == nil && strings.HasPrefix(string(cmd), "php-fpm: master process (") {
			return nil
		}
	}
	for _, id := range ids {
		add(id, "a running "+base+" process")
	}
	return nil
}

// The leader can be a zombie while other threads still run. Their credentials
// may differ from the leader's, so a missing executable cannot exclude them.
func procNoUserspace(stat string) (bool, error) {
	_, rest, ok := strings.Cut(stat, " (")
	end := strings.LastIndex(rest, ") ")
	if !ok || end < 0 {
		return false, errors.New("invalid process liveness")
	}
	fields := strings.Fields(rest[end+2:])
	if len(fields) < 18 {
		return false, errors.New("invalid process liveness")
	}
	flags, flagsErr := strconv.ParseUint(fields[6], 10, 64)
	threads, threadsErr := strconv.ParseUint(fields[17], 10, 32)
	if flagsErr != nil || threadsErr != nil || threads == 0 || len(fields[0]) != 1 {
		return false, errors.New("invalid process liveness")
	}
	// PF_KTHREAD is kernel supplied, unlike comm and cmdline, and works on
	// kernels older than the Kthread field in /proc/PID/status.
	if flags&0x00200000 != 0 {
		return true, nil
	}
	if threads != 1 {
		return false, errors.New("cannot inspect surviving process threads without an executable")
	}
	return fields[0] == "Z" || fields[0] == "X", nil
}

// A proc file opened before exit can return ESRCH rather than ENOENT.
func procProcessExited(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ESRCH)
}

// procRealUID reads the real UID from a procfs status file. A user cannot
// start a process whose real UID is root; setuid programs keep the caller's.
func procRealUID(status string) (uint32, error) {
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) == 4 {
				if n, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					return uint32(n), nil
				}
			}
			break
		}
	}
	return 0, errors.New("invalid process credentials")
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

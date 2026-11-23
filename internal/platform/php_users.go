package platform

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PHPRuntimeUsers maps each user PHP or CGI runs as on this host to what
// runs as it: a PHP-FPM pool, a running PHP or CGI worker, or Apache's own
// PHP or CGI module. Code a site runs can act as any of these users.
func PHPRuntimeUsers() map[string]string { return phpRuntimeUsers("/") }

// fpmConfigGlobs are where distributions and panels keep PHP-FPM pools.
var fpmConfigGlobs = []string{
	"etc/php/*/fpm/php-fpm.conf",
	"etc/php/*/fpm/pool.d/*.conf",
	"etc/php-fpm.conf",
	"etc/php-fpm.d/*.conf",
	"etc/opt/remi/php*/php-fpm.d/*.conf",
	"opt/remi/php*/root/etc/php-fpm.d/*.conf",
	"usr/local/etc/php-fpm.d/*.conf",
	"usr/local/php*/etc/php-fpm.d/*.conf",
	"opt/plesk/php/*/etc/php-fpm.d/*.conf",
	"opt/alt/php*/etc/php-fpm.d/*.conf",
	"opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
}

// phpWorkerName matches the PHP and CGI binaries a web server hands requests
// to. The PHP command-line binary is not one.
var phpWorkerName = regexp.MustCompile(`^(php-cgi|php-fpm|lsphp)[0-9.]*$|^fcgiwrap$`)

func phpRuntimeUsers(root string) map[string]string {
	out := map[string]string{}
	add := func(user, source string) {
		if user != "" && out[user] == "" {
			out[user] = source
		}
	}
	for _, glob := range fpmConfigGlobs {
		paths, _ := filepath.Glob(filepath.Join(root, glob))
		for _, path := range paths {
			for _, pool := range fpmPools(path) {
				add(pool.user, "PHP-FPM pool "+pool.name)
			}
		}
	}

	names := passwdNamesByUID(root)
	procs, _ := filepath.Glob(filepath.Join(root, "proc", "[0-9]*"))
	for _, dir := range procs {
		exe, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			continue
		}
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		if !phpWorkerName.MatchString(base) {
			continue
		}
		uid := procEffectiveUID(dir)
		if uid == "" || uid == "0" {
			continue
		}
		user := names[uid]
		if user == "" {
			user = "uid " + uid
		}
		add(user, "a running "+base+" process")
	}

	if user := debianApacheUser(root); user != "" {
		if matches, _ := filepath.Glob(filepath.Join(root, "etc/apache2/mods-enabled/php*.load")); len(matches) > 0 {
			add(user, "Apache's PHP module")
		}
		for _, mod := range []string{"cgi.load", "cgid.load"} {
			if _, err := os.Stat(filepath.Join(root, "etc/apache2/mods-enabled", mod)); err == nil {
				add(user, "Apache's CGI module")
			}
		}
	}
	if user := rhelApacheUser(root); user != "" {
		confs, _ := filepath.Glob(filepath.Join(root, "etc/httpd/conf.modules.d/*.conf"))
		for _, conf := range confs {
			for _, module := range loadedModules(conf) {
				switch {
				case strings.HasPrefix(module, "php"):
					add(user, "Apache's PHP module")
				case module == "cgi_module" || module == "cgid_module":
					add(user, "Apache's CGI module")
				}
			}
		}
	}
	return out
}

type fpmPool struct{ name, user string }

// fpmPools reads the pools in one PHP-FPM file and the user each runs as.
// $pool in a value is the pool's name.
func fpmPools(path string) []fpmPool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pools []fpmPool
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		// A commented line is neither a section nor a user key.
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "user" || section == "" || section == "global" {
			continue
		}
		value, _, _ = strings.Cut(value, ";")
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		value = strings.NewReplacer("${pool}", section, "$pool", section).Replace(value)
		pools = append(pools, fpmPool{name: section, user: value})
	}
	return pools
}

func passwdNamesByUID(root string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(root, "etc/passwd"))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 3 && out[fields[2]] == "" {
			out[fields[2]] = fields[0]
		}
	}
	return out
}

// procEffectiveUID reads the effective uid from a /proc/PID/status file.
func procEffectiveUID(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

// debianApacheUser is the user Debian's Apache runs as, or "" without one.
func debianApacheUser(root string) string {
	if _, err := os.Stat(filepath.Join(root, "etc/apache2")); err != nil {
		return ""
	}
	data, _ := os.ReadFile(filepath.Join(root, "etc/apache2/envvars"))
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "export APACHE_RUN_USER="); ok {
			if user := strings.Trim(strings.TrimSpace(rest), `"'`); user != "" && !strings.Contains(user, "$") {
				return user
			}
		}
	}
	return "www-data"
}

// rhelApacheUser is the user RHEL's Apache runs as, or "" without one.
func rhelApacheUser(root string) string {
	if _, err := os.Stat(filepath.Join(root, "etc/httpd")); err != nil {
		return ""
	}
	data, _ := os.ReadFile(filepath.Join(root, "etc/httpd/conf/httpd.conf"))
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "User" && !strings.Contains(fields[1], "$") {
			return strings.Trim(fields[1], `"'`)
		}
	}
	return "apache"
}

// loadedModules lists the modules a conf file loads with LoadModule lines
// that are not commented out.
func loadedModules(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "LoadModule" {
			out = append(out, fields[1])
		}
	}
	return out
}

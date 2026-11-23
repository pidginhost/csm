package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// apacheScriptModules run site code as Apache's user unless something setup
// cannot see isolates them (suEXEC, a WSGI daemon user, per-vhost users), so
// each one counts: refusing forwarded addresses is the safe answer.
var apacheScriptModules = map[string]string{
	"cgi_module":       "Apache's CGI module",
	"cgid_module":      "Apache's CGI module",
	"fcgid_module":     "Apache's FastCGI module",
	"fastcgi_module":   "Apache's FastCGI module",
	"passenger_module": "Apache's Passenger module",
	"wsgi_module":      "Apache's WSGI module",
	"perl_module":      "Apache's Perl module",
	"python_module":    "Apache's Python module",
	"lua_module":       "Apache's Lua module",
	"lsapi_module":     "Apache's LSAPI module",
}

type apacheReader struct {
	root, serverRoot, user, envUser string
	source                          string
	seen                            map[string]bool
}

func apacheRuntimeUsers(root string, add func(string, string) error) error {
	for _, layout := range []struct{ dir, user string }{
		{"etc/apache2", "www-data"},
		{"etc/httpd", "apache"},
		{"usr/local/apache", "apache"},
	} {
		if _, err := os.Stat(filepath.Join(root, layout.dir)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		r := apacheReader{root: root, serverRoot: "/" + layout.dir, user: layout.user, envUser: layout.user, seen: map[string]bool{}}
		if data, err := os.ReadFile(filepath.Join(root, layout.dir, "envvars")); err == nil { // #nosec G304 -- fixed Apache layout under the internal host or fixture root.
			for _, raw := range strings.Split(string(data), "\n") {
				raw = strings.TrimPrefix(strings.TrimSpace(raw), "export ")
				if value, ok := strings.CutPrefix(raw, "APACHE_RUN_USER="); ok {
					parsed, parseErr := runtimeConfigLine(value, '#')
					if parseErr != nil {
						return parseErr
					}
					r.envUser = runtimeConfigValue(parsed)
					r.user = r.envUser
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		for _, glob := range []string{"apache2.conf", "conf/httpd.conf", "mods-enabled/*.load", "conf.modules.d/*.conf", "conf.d/*.conf"} {
			paths, err := runtimeConfigGlob(filepath.Join(root, layout.dir, glob))
			if err != nil {
				return err
			}
			for _, path := range paths {
				if !r.seen[path] {
					if err := r.read(path, 0); err != nil {
						return err
					}
				}
			}
		}
		if r.source != "" {
			if strings.Contains(r.user, "$") || r.user == "" {
				return errors.New("cannot resolve Apache's PHP/CGI user")
			}
			if err := add(r.user, r.source); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *apacheReader) read(path string, depth int) error {
	if depth > 128 {
		return errors.New("apache include recursion exceeds the supported depth")
	}
	data, err := os.ReadFile(path) // #nosec G304 G703 -- read the same administrator-configured include paths as Apache.
	if err != nil {
		return fmt.Errorf("read Apache configuration: %w", err)
	}
	r.seen[path] = true
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := runtimeConfigValue(strings.TrimSpace(line[len(fields[0]):]))
		switch key {
		case "user":
			r.user = strings.ReplaceAll(value, "${APACHE_RUN_USER}", r.envUser)
		case "serverroot":
			r.serverRoot = value
		case "include", "includeoptional":
			if strings.Contains(value, "$") {
				return errors.New("cannot resolve Apache PHP/CGI include")
			}
			if !filepath.IsAbs(value) {
				value = filepath.Join(r.serverRoot, value)
			}
			paths, err := runtimeConfigGlob(filepath.Join(r.root, value))
			if err != nil {
				return err
			}
			for _, include := range paths {
				if err := r.read(include, depth+1); err != nil {
					return err
				}
			}
		case "loadmodule":
			module := strings.ToLower(runtimeConfigValue(fields[1]))
			if strings.HasPrefix(module, "php") {
				r.source = "Apache's PHP module"
			} else if source, ok := apacheScriptModules[module]; ok && r.source == "" {
				r.source = source
			}
		}
	}
	return nil
}

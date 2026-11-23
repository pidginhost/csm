package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Read main files before orphan pool files so includes retain their pool
// context and overridden values use FPM's last assignment.
var fpmConfigGlobs = []string{
	"etc/php/*/fpm/php-fpm.conf",
	"etc/php-fpm.conf",
	"etc/opt/remi/php*/php-fpm.conf",
	"opt/remi/php*/root/etc/php-fpm.conf",
	"usr/local/etc/php-fpm.conf",
	"usr/local/php*/etc/php-fpm.conf",
	"opt/plesk/php/*/etc/php-fpm.conf",
	"opt/alt/php*/etc/php-fpm.conf",
	"opt/cpanel/ea-php*/root/etc/php-fpm.conf",
	"etc/php/*/fpm/pool.d/*.conf",
	"etc/php-fpm.d/*.conf",
	"etc/opt/remi/php*/php-fpm.d/*.conf",
	"opt/remi/php*/root/etc/php-fpm.d/*.conf",
	"usr/local/etc/php-fpm.d/*.conf",
	"usr/local/php*/etc/php-fpm.d/*.conf",
	"usr/local/directadmin/data/users/*/php/php-fpm*.conf",
	"opt/plesk/php/*/etc/php-fpm.d/*.conf",
	"opt/alt/php*/etc/php-fpm.d/*.conf",
	"opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
}

type fpmPool struct{ name, user string }

type fpmReader struct {
	root    string
	section string
	users   map[string]string
	names   map[string]string
	seen    map[string]bool
}

func phpFPMPools(root string) ([]fpmPool, error) {
	seen := map[string]bool{}
	var out []fpmPool
	for _, glob := range fpmConfigGlobs {
		paths, err := runtimeConfigGlob(filepath.Join(root, glob))
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			r := fpmReader{root: root, users: map[string]string{}, names: map[string]string{}, seen: seen}
			if err := r.read(path, 0); err != nil {
				return nil, err
			}
			var names []string
			for name := range r.users {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				out = append(out, fpmPool{name, r.users[name]})
			}
		}
	}
	return out, nil
}

func (r *fpmReader) read(path string, depth int) error {
	if depth > 5 {
		return errors.New("PHP-FPM include recursion exceeds the supported depth")
	}
	data, err := os.ReadFile(path) // #nosec G304 G703 -- read the same administrator-configured include paths as PHP-FPM.
	if err != nil {
		return fmt.Errorf("read PHP-FPM configuration: %w", err)
	}
	r.seen[path] = true
	for _, raw := range strings.Split(string(data), "\n") {
		line, err := runtimeConfigLine(raw, ';')
		if err != nil {
			return fmt.Errorf("parse PHP-FPM configuration: %w", err)
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := runtimeConfigValue(line[1 : len(line)-1])
			key := strings.ToLower(name)
			if prior, ok := r.names[key]; ok {
				r.section = prior
			} else {
				r.section, r.names[key] = name, name
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "include" && key != "user" {
			continue
		}
		value = runtimeConfigValue(value)
		value = strings.NewReplacer("${pool}", r.section, "$pool", r.section).Replace(value)
		if strings.Contains(value, "$") || value == "" {
			return errors.New("unresolved PHP-FPM user or include")
		}
		switch key {
		case "include":
			// Relative includes use FPM's build/runtime prefix, not the
			// directory of this file. Do not guess that prefix.
			if !filepath.IsAbs(value) {
				return errors.New("cannot resolve relative PHP-FPM include; use an absolute include")
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
		case "user":
			if r.section != "" && !strings.EqualFold(r.section, "global") {
				r.users[r.section] = value
			}
		}
	}
	return nil
}

// Comment delimiters inside quotes are literal characters in these config
// formats. Reject unclosed quotes instead of extracting a partial identity.
func runtimeConfigLine(line string, comment byte) (string, error) {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == '\\' && i+1 < len(line) {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == comment:
			return strings.TrimSpace(line[:i]), nil
		case c == '\'' || c == '"':
			quote = c
		}
	}
	if quote != 0 {
		return "", errors.New("unclosed configuration quote")
	}
	return strings.TrimSpace(line), nil
}

func runtimeConfigValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

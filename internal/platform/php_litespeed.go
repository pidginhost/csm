package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var liteSpeedServerName = regexp.MustCompile(`^(lshttpd|litespeed|openlitespeed)(\.[0-9]+)*$`)

// Running servers also contribute their installation directory through the
// process inspection, so custom installs do not depend on the default path.
func litespeedRuntimeUsers(root string, add func(string, string) error) error {
	info := Info{}
	if root == "/" {
		info = Detect()
	}
	return liteSpeedInstalledUsers(root, info, add)
}

func liteSpeedInstalledUsers(root string, info Info, add func(string, string) error) error {
	installs := []string{"/usr/local/lsws"}
	if info.LiteSpeedBinary != "" {
		if !filepath.IsAbs(info.LiteSpeedBinary) || filepath.Base(filepath.Dir(info.LiteSpeedBinary)) != "bin" {
			return errors.New("cannot locate detected LiteSpeed server configuration")
		}
		install := filepath.Dir(filepath.Dir(info.LiteSpeedBinary))
		if install != installs[0] {
			installs = append(installs, install)
		}
	}
	found := false
	for _, install := range installs {
		path := filepath.Join(root, install, "conf")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if info.LiteSpeedBinary != "" && install == filepath.Dir(filepath.Dir(info.LiteSpeedBinary)) {
				return errors.New("missing detected LiteSpeed configuration")
			}
			continue
		} else if err != nil {
			return fmt.Errorf("inspect LiteSpeed: %w", err)
		}
		found = true
		if err := liteSpeedConfigUsers(path, add); err != nil {
			return err
		}
	}
	if !found && info.WebServer == WSLiteSpeed {
		return errors.New("cannot locate detected LiteSpeed server configuration")
	}
	return nil
}

// Only explicit Enterprise PHP suEXEC proves isolation. OpenLiteSpeed sets
// users per application and virtual host, so its server user always counts.
func liteSpeedConfigUsers(conf string, add func(string, string) error) error {
	found := false
	for _, name := range []string{"httpd_config.xml", "httpd_config.conf"} {
		data, err := os.ReadFile(filepath.Join(conf, name)) // #nosec G304 G703 -- server configuration under the installed or running LiteSpeed directory.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read LiteSpeed configuration: %w", err)
		}
		found = true
		var user string
		var isolated bool
		if name == "httpd_config.xml" {
			user, isolated, err = parseLiteSpeedServerXML(data)
		} else {
			user, err = openLiteSpeedServerUser(string(data))
		}
		if err != nil {
			return err
		}
		if isolated {
			continue
		}
		if user == "" {
			return errors.New("missing LiteSpeed server user")
		}
		if err := add(user, "LiteSpeed's PHP handler"); err != nil {
			return err
		}
	}
	if !found {
		return errors.New("missing LiteSpeed server configuration")
	}
	return nil
}

func openLiteSpeedServerUser(data string) (string, error) {
	depth := 0
	user := ""
	for _, raw := range strings.Split(data, "\n") {
		line, err := runtimeConfigLine(raw, '#')
		if err != nil {
			return "", err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if depth == 0 {
			switch strings.ToLower(fields[0]) {
			case "include":
				// Included settings can replace the server user. Without inspecting
				// their effective order, the main document alone proves nothing.
				return "", errors.New("cannot verify OpenLiteSpeed server includes")
			case "user":
				if len(fields) != 2 || user != "" {
					return "", errors.New("ambiguous OpenLiteSpeed server user")
				}
				user = runtimeConfigValue(fields[1])
			}
		}
		// Block delimiters only count outside quoted values. Reject inline
		// directives after a closing block rather than overlooking a server user.
		var quote rune
		escaped := false
		for i, c := range line {
			if escaped {
				escaped = false
				continue
			}
			if quote != 0 {
				switch c {
				case '\\':
					escaped = true
				case quote:
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 || strings.TrimSpace(line[i+1:]) != "" {
					return "", errors.New("unsupported OpenLiteSpeed block syntax")
				}
			}
		}
	}
	if depth != 0 {
		return "", errors.New("unclosed OpenLiteSpeed configuration block")
	}
	return user, nil
}

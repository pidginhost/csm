package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	lswsXMLUser   = regexp.MustCompile(`<user>\s*([^<\s]+)\s*</user>`)
	lswsXMLSuExec = regexp.MustCompile(`<phpSuExec>\s*([0-9]+)\s*</phpSuExec>`)
)

// litespeedRuntimeUsers counts LiteSpeed's server user, which runs PHP for
// sites unless PHP suEXEC is on. Only an explicit phpSuExec of 1 or 2 in the
// Enterprise configuration proves otherwise; OpenLiteSpeed sets the user per
// external application and virtual host, which setup does not read, so it
// always counts. A configuration that cannot be read proves nothing.
func litespeedRuntimeUsers(root string, add func(string, string) error) error {
	conf := filepath.Join(root, "usr/local/lsws/conf")
	if _, err := os.Stat(conf); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect LiteSpeed: %w", err)
	}
	user := "nobody"
	data, err := os.ReadFile(filepath.Join(conf, "httpd_config.xml")) // #nosec G304 -- fixed LiteSpeed path under the host or fixture root.
	switch {
	case err == nil:
		if m := lswsXMLUser.FindSubmatch(data); m != nil {
			user = string(m[1])
		}
		if m := lswsXMLSuExec.FindSubmatch(data); m != nil && (string(m[1]) == "1" || string(m[1]) == "2") {
			return nil
		}
	case os.IsNotExist(err):
		data, err = os.ReadFile(filepath.Join(conf, "httpd_config.conf")) // #nosec G304 -- fixed OpenLiteSpeed path under the host or fixture root.
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read LiteSpeed configuration: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "user" {
				user = f[1]
			}
		}
	default:
		return fmt.Errorf("read LiteSpeed configuration: %w", err)
	}
	return add(user, "LiteSpeed's PHP handler")
}

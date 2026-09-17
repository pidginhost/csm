package main

import (
	"strings"
	"testing"
)

func TestSystemdServiceLimitsConfigurationWrites(t *testing.T) {
	allowed := map[string]bool{
		"/etc/csm":                  true,
		"/etc/audit":                true,
		"/etc/modprobe.d":           true,
		"/etc/apache2/conf.d":       true,
		"/etc/apache2/conf-enabled": true,
		"/etc/httpd/conf.d":         true,
		"/etc/nginx/conf.d":         true,
	}
	for entry := range unitDirectiveFields(systemdServiceUnit("/opt/csm/csm"), "ReadWritePaths") {
		path := strings.TrimPrefix(entry, "-")
		if (path == "/" || path == "/etc" || strings.HasPrefix(path, "/etc/")) && !allowed[path] {
			t.Errorf("service grants unrelated configuration writes: %s", entry)
		}
	}
	for path := range allowed {
		paths := unitDirectiveFields(systemdServiceUnit("/opt/csm/csm"), "ReadWritePaths")
		if !paths[path] && !paths["-"+path] {
			t.Errorf("missing managed configuration directory %s", path)
		}
	}
}

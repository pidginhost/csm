package platform

import "path/filepath"

// IsCPanelCentralAccessLog identifies the server logs whose paths carry
// cPanel's proxy routing. An arbitrary access_logs override can name a
// website log, so only the platform's own central paths and their aliases
// establish that provenance.
func (i Info) IsCPanelCentralAccessLog(path string) bool {
	if i.Panel != PanelCPanel || path == "" {
		return false
	}
	defaults := Info{OS: i.OS, Panel: i.Panel, WebServer: i.WebServer}
	populatePaths(&defaults)
	path = resolvedAccessLogPath(path)
	for _, candidate := range defaults.AccessLogPaths {
		if path == resolvedAccessLogPath(candidate) {
			return true
		}
	}
	return false
}

func resolvedAccessLogPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	path = absolute
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}

package platform

import (
	"encoding/xml"
	"os"
	"strings"
)

// liteSpeedRunsPHPAsServer reports whether LiteSpeed runs PHP as its own
// user, so any site's code can write what LiteSpeed writes: PHP suEXEC is
// off (phpSuExec 0), or the setting is missing, repeated, unknown or
// unreadable, which counts the same.
func liteSpeedRunsPHPAsServer(path string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- LiteSpeed's fixed configuration path or a test file
	if err != nil {
		return true
	}
	var c struct {
		XMLName   xml.Name `xml:"httpServerConfig"`
		PHPSuExec []string `xml:"phpSuExec"`
	}
	if xml.Unmarshal(data, &c) != nil || len(c.PHPSuExec) != 1 {
		return true
	}
	v := strings.TrimSpace(c.PHPSuExec[0])
	return v != "1" && v != "2"
}

// serverRunsSiteCode reports a LiteSpeed host that runs PHP as its own user.
func serverRunsSiteCode(ws WebServer) bool {
	return ws == WSLiteSpeed && liteSpeedRunsPHPAsServer(LiteSpeedConfigPath)
}

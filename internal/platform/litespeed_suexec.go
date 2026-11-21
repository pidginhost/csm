package platform

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"strings"
)

// liteSpeedRunsPHPAsServer reports whether LiteSpeed runs PHP as its own
// user, so any site's code can write what LiteSpeed writes. Only a single,
// plain phpSuExec setting of 1 or 2 in a complete document proves isolation.
func liteSpeedRunsPHPAsServer(path string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- LiteSpeed's fixed configuration path or a test file
	if err != nil {
		return true
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, settings := 0, 0
	root, inSetting := false, false
	var value strings.Builder
	for {
		token, err := d.Token()
		if err == io.EOF {
			v := strings.TrimSpace(value.String())
			return !root || depth != 0 || settings != 1 || (v != "1" && v != "2")
		}
		if err != nil {
			return true
		}
		switch t := token.(type) {
		case xml.StartElement:
			if inSetting {
				return true
			}
			if depth == 0 {
				if root || t.Name != (xml.Name{Local: "httpServerConfig"}) {
					return true
				}
				root = true
			}
			if t.Name.Local == "phpSuExec" {
				settings++
				if depth != 1 || settings != 1 || t.Name.Space != "" || len(t.Attr) != 0 {
					return true
				}
				inSetting = true
			}
			depth++
		case xml.EndElement:
			if inSetting {
				inSetting = false
			}
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return true
			}
			if inSetting {
				value.Write(t)
			}
		}
	}
}

// ServerRunsSiteCode reads the current LiteSpeed PHP isolation setting.
// Unlike Detect's snapshot, callers can use it to revoke trust at runtime.
func ServerRunsSiteCode(ws WebServer) bool {
	return ws == WSLiteSpeed && liteSpeedRunsPHPAsServer(LiteSpeedConfigPath)
}

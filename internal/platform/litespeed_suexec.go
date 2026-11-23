package platform

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
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
	_, isolated, err := parseLiteSpeedServerXML(data)
	return err != nil || !isolated
}

// Only direct children of the server document describe the server identity.
// Nested application users and commented settings must never establish trust.
func parseLiteSpeedServerXML(data []byte) (string, bool, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	root := false
	setting := ""
	values := map[string]string{}
	var value strings.Builder
	invalid := errors.New("ambiguous LiteSpeed server configuration")
	for {
		token, err := d.Token()
		if err == io.EOF {
			if !root || depth != 0 {
				return "", false, invalid
			}
			return values["user"], values["phpSuExec"] == "1" || values["phpSuExec"] == "2", nil
		}
		if err != nil {
			return "", false, fmt.Errorf("parse LiteSpeed configuration: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			if setting != "" {
				return "", false, invalid
			}
			if depth == 0 {
				if root || t.Name != (xml.Name{Local: "httpServerConfig"}) {
					return "", false, invalid
				}
				root = true
			}
			if t.Name.Local == "phpSuExec" || (depth == 1 && t.Name.Local == "user") {
				if _, duplicate := values[t.Name.Local]; duplicate || depth != 1 || t.Name.Space != "" || len(t.Attr) != 0 {
					return "", false, invalid
				}
				setting = t.Name.Local
				value.Reset()
			}
			depth++
		case xml.EndElement:
			if setting != "" {
				values[setting] = strings.TrimSpace(value.String())
				setting = ""
			}
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return "", false, invalid
			}
			if setting != "" {
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

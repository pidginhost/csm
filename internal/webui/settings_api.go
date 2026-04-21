package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"gopkg.in/yaml.v3"
)

const settingsURLPrefix = "/api/v1/settings/"

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.apiSettingsGet(w, r)
	case http.MethodPost:
		s.requireCSRF(http.HandlerFunc(s.apiSettingsPost)).ServeHTTP(w, r)
	default:
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	sectionID := strings.TrimPrefix(r.URL.Path, settingsURLPrefix)
	if sectionID == "" || strings.Contains(sectionID, "/") {
		writeJSONError(w, "section required", http.StatusBadRequest)
		return
	}
	if sectionID == "restart" {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	section, ok := LookupSettingsSection(sectionID)
	if !ok {
		writeJSONError(w, "unknown section", http.StatusNotFound)
		return
	}

	diskBytes, err := os.ReadFile(s.cfg.ConfigFile) // #nosec G304 -- operator-configured config path
	if err != nil {
		writeJSONError(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, err := config.LoadBytes(diskBytes)
	if err != nil {
		writeJSONError(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk.ConfigFile = s.cfg.ConfigFile

	redacted := config.Redact(disk)
	values, err := extractSectionValues(diskBytes, redacted, section)
	if err != nil {
		writeJSONError(w, "extract: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var pendingFields []string
	if live := config.Active(); live != nil {
		diff := config.Diff(live, disk)
		for _, c := range diff {
			if c.Field == section.YAMLPath || strings.HasPrefix(c.Field, section.YAMLPath+".") {
				pendingFields = append(pendingFields, c.Field)
			}
		}
	}

	w.Header().Set("ETag", disk.Integrity.ConfigHash)
	writeJSON(w, map[string]interface{}{
		"section":         section,
		"values":          values,
		"etag":            disk.Integrity.ConfigHash,
		"pending_restart": len(pendingFields) > 0,
		"pending_fields":  pendingFields,
	})
}

func extractSectionValues(rawBytes []byte, effectiveCfg *config.Config, section SettingsSection) (map[string]interface{}, error) {
	effective, err := extractSectionEffectiveValues(effectiveCfg, section)
	if err != nil {
		return nil, err
	}
	raw, err := extractSectionRawValues(rawBytes, section)
	if err != nil {
		return nil, err
	}
	values := make(map[string]interface{}, len(effective))
	for k, v := range effective {
		values[k] = v
	}
	overlayNullableState(section, values, raw)
	return values, nil
}

func extractSectionEffectiveValues(cfg *config.Config, section SettingsSection) (map[string]interface{}, error) {
	var wrapper map[string]interface{}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	raw, ok := wrapper[section.YAMLPath]
	if !ok {
		return map[string]interface{}{}, nil
	}
	if _, isMap := raw.(map[string]interface{}); !isMap {
		return map[string]interface{}{section.YAMLPath: raw}, nil
	}
	return raw.(map[string]interface{}), nil
}

func extractSectionRawValues(rawBytes []byte, section SettingsSection) (map[string]interface{}, error) {
	var wrapper map[string]interface{}
	if err := yaml.Unmarshal(rawBytes, &wrapper); err != nil {
		return nil, err
	}
	raw, ok := wrapper[section.YAMLPath]
	if !ok {
		return map[string]interface{}{}, nil
	}
	if _, isMap := raw.(map[string]interface{}); !isMap {
		return map[string]interface{}{section.YAMLPath: raw}, nil
	}
	return raw.(map[string]interface{}), nil
}

func overlayNullableState(section SettingsSection, values, raw map[string]interface{}) {
	for _, field := range section.Fields {
		if !field.Nullable {
			continue
		}
		// All v1 nullable fields are direct children of the section.
		if strings.Contains(field.YAMLPath, ".") {
			continue
		}
		if v, ok := raw[field.YAMLPath]; ok {
			values[field.YAMLPath] = v
			continue
		}
		values[field.YAMLPath] = nil
	}
}

// apiSettingsPost is a placeholder until Task 6 lands.
func (s *Server) apiSettingsPost(w http.ResponseWriter, _ *http.Request) {
	writeJSONError(w, "not implemented", http.StatusNotImplemented)
}

// placeholder to satisfy imports until Task 6 lands.
var _ = reflect.TypeOf(0)
var _ = fmt.Sprintf
var _ = json.Marshal

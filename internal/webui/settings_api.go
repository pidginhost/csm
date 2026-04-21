package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
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

func (s *Server) apiSettingsPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sectionID := strings.TrimPrefix(r.URL.Path, settingsURLPrefix)
	if sectionID == "" || strings.Contains(sectionID, "/") {
		writeJSONError(w, "section required", http.StatusBadRequest)
		return
	}
	section, ok := LookupSettingsSection(sectionID)
	if !ok {
		writeJSONError(w, "unknown section", http.StatusNotFound)
		return
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		writeJSONError(w, "If-Match header required", http.StatusBadRequest)
		return
	}

	var body struct {
		Changes map[string]json.RawMessage `json:"changes"`
	}
	if err := decodeJSONBodyLimited(w, r, 256*1024, &body); err != nil {
		writeJSONError(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}

	diskBytes, err := os.ReadFile(s.cfg.ConfigFile) // #nosec G304 -- operator-supplied config path
	if err != nil {
		writeJSONError(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk, err := config.LoadBytes(diskBytes)
	if err != nil {
		writeJSONError(w, "parse config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	disk.ConfigFile = s.cfg.ConfigFile
	if disk.Integrity.ConfigHash != ifMatch {
		writeJSONError(w, "config changed on disk, reload", http.StatusPreconditionFailed)
		return
	}

	clone := *disk
	if disk.Firewall != nil {
		fw := *disk.Firewall
		clone.Firewall = &fw
	}

	yamlChanges, errs := buildChangeSet(section, &clone, body.Changes)
	if len(errs) > 0 {
		writeValidationErrors(w, errs)
		return
	}

	validationResults := append(config.Validate(&clone), config.ValidateDeepSection(&clone, section.ID)...)
	fieldErrors, warnings := splitValidationResults(validationResults)
	if len(fieldErrors) > 0 {
		writeValidationErrors(w, fieldErrors)
		return
	}

	diff := config.Diff(disk, &clone)
	var restartFields []string
	for _, c := range diff {
		if c.Tag != config.TagSafe {
			restartFields = append(restartFields, c.Field)
		}
	}

	edited, err := config.YAMLEdit(diskBytes, yamlChanges)
	if err != nil {
		writeJSONError(w, "yaml edit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := integrity.SignAndSavePreserving(s.cfg.ConfigFile, edited, &clone, disk.Integrity.BinaryHash); err != nil {
		writeJSONError(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newETag := clone.Integrity.ConfigHash

	if len(restartFields) == 0 {
		config.SetActive(&clone)
	} else if live := config.Active(); live != nil {
		livePatched := *live
		livePatched.Integrity.ConfigHash = newETag
		config.SetActive(&livePatched)
	}

	var applied []string
	for _, c := range diff {
		applied = append(applied, c.Field)
	}

	s.auditLog(r, "settings-save", sectionID, auditDetailsFor(section, body.Changes))

	writeJSON(w, map[string]interface{}{
		"applied":          applied,
		"requires_restart": restartFields,
		"pending_restart":  len(restartFields) > 0,
		"warnings":         warnings,
		"new_etag":         newETag,
	})
}

type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func splitValidationResults(results []config.ValidationResult) (errs []fieldError, warnings []fieldError) {
	for _, v := range results {
		if v.Level == "error" {
			errs = append(errs, fieldError{Field: v.Field, Message: v.Message})
			continue
		}
		if v.Level == "warn" {
			warnings = append(warnings, fieldError{Field: v.Field, Message: v.Message})
		}
	}
	return errs, warnings
}

func writeValidationErrors(w http.ResponseWriter, errs []fieldError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": errs})
}

func buildChangeSet(section SettingsSection, clone *config.Config, changes map[string]json.RawMessage) ([]config.YAMLChange, []fieldError) {
	var out []config.YAMLChange
	var errs []fieldError

	for key, raw := range changes {
		field := lookupSchemaField(section, key)
		if field == nil {
			errs = append(errs, fieldError{Field: key, Message: "unknown field"})
			continue
		}
		if field.Secret {
			var sv string
			if err := json.Unmarshal(raw, &sv); err == nil && sv == "***REDACTED***" {
				continue
			}
		}

		fullPath := section.YAMLPath
		if key != "" {
			fullPath = section.YAMLPath + "." + key
		}
		decoded, err := decodeJSONForYAML(raw, field)
		if err != nil {
			errs = append(errs, fieldError{Field: key, Message: "decode: " + err.Error()})
			continue
		}
		out = append(out, config.YAMLChange{Path: strings.Split(fullPath, "."), Value: decoded})
		if err := applyToClone(clone, strings.Split(fullPath, "."), raw); err != nil {
			errs = append(errs, fieldError{Field: key, Message: err.Error()})
		}
	}
	return out, errs
}

func lookupSchemaField(section SettingsSection, key string) *SettingsField {
	for i := range section.Fields {
		if section.Fields[i].YAMLPath == key {
			return &section.Fields[i]
		}
	}
	return nil
}

func decodeJSONForYAML(raw json.RawMessage, field *SettingsField) (interface{}, error) {
	if string(raw) == "null" {
		if !field.Nullable {
			return nil, fmt.Errorf("null is only allowed for nullable fields")
		}
		return nil, nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func applyToClone(cfg *config.Config, path []string, raw json.RawMessage) error {
	v := reflect.ValueOf(cfg).Elem()
	for i, key := range path {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return fmt.Errorf("path %v: element %d is not a struct", path, i)
		}
		field, ok := fieldByYAMLTag(v.Type(), key)
		if !ok {
			return fmt.Errorf("no yaml field %q under %s", key, strings.Join(path[:i], "."))
		}
		v = v.FieldByIndex(field.Index)
	}
	ptr := reflect.New(v.Type())
	if err := json.Unmarshal(raw, ptr.Interface()); err != nil {
		return fmt.Errorf("unmarshal into %s: %w", v.Type(), err)
	}
	v.Set(ptr.Elem())
	return nil
}

func fieldByYAMLTag(t reflect.Type, yamlName string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" {
			continue
		}
		name := tag
		if idx := strings.IndexByte(tag, ','); idx >= 0 {
			name = tag[:idx]
		}
		if name == yamlName {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func auditDetailsFor(section SettingsSection, changes map[string]json.RawMessage) string {
	redacted := make(map[string]interface{}, len(changes))
	for k, raw := range changes {
		if field := lookupSchemaField(section, k); field != nil && field.Secret {
			redacted[k] = "***"
			continue
		}
		var v interface{}
		_ = json.Unmarshal(raw, &v)
		redacted[k] = v
	}
	b, _ := json.Marshal(redacted)
	return string(b)
}

// defaultRestartDaemon is the production implementation. Tests override
// s.restartDaemon with a fake.
func defaultRestartDaemon() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- fixed argv, no operator input interpolated.
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "csm")
	return cmd.CombinedOutput()
}

// apiSettingsRestart handles POST /api/v1/settings/restart. Returns 202
// on successful systemctl invocation (the server process may die
// mid-response, so the frontend treats a connection reset as expected).
// Returns 500 + stderr truncated to 4 KiB on failure before teardown.
func (s *Server) apiSettingsRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.auditLog(r, "settings-restart", "daemon", "")

	output, err := s.restartDaemon()
	if err != nil {
		truncated := output
		if len(truncated) > 4096 {
			truncated = truncated[:4096]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  err.Error(),
			"stderr": string(truncated),
		})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"restart issued"}`))
}

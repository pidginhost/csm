package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"gopkg.in/yaml.v3"
)

const settingsURLPrefix = "/api/v1/settings/"

type pendingSettingsSection struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func pendingRestartSections(live, disk *config.Config) []pendingSettingsSection {
	if live == nil || disk == nil {
		return nil
	}

	seen := map[string]struct{}{}
	for _, c := range config.Diff(live, disk) {
		if c.Tag == config.TagSafe {
			continue
		}
		for _, section := range settingsSections {
			if c.Field == section.YAMLPath || strings.HasPrefix(c.Field, section.YAMLPath+".") {
				seen[section.ID] = struct{}{}
				break
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	out := make([]pendingSettingsSection, 0, len(seen))
	for _, section := range settingsSections {
		if _, ok := seen[section.ID]; ok {
			out = append(out, pendingSettingsSection{ID: section.ID, Title: section.Title})
		}
	}
	return out
}

func cloneConfigForSettingsApply(src *config.Config) config.Config {
	clone := *src
	if src.Firewall != nil {
		fw := *src.Firewall
		clone.Firewall = &fw
	}
	return clone
}

func (s *Server) apiSettingsSections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, map[string]interface{}{
		"groups":   SectionGroupOrder,
		"sections": AllSettingsSections(),
	})
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	// This prefix serves both GET (read settings) and POST (update); CSRF is
	// enforced only on the mutating POST path.
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
	resolveFieldOptions(&section)

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
	var pendingSections []pendingSettingsSection
	if live := config.Active(); live != nil {
		diff := config.Diff(live, disk)
		for _, c := range diff {
			if c.Tag != config.TagSafe && (c.Field == section.YAMLPath || strings.HasPrefix(c.Field, section.YAMLPath+".")) {
				pendingFields = append(pendingFields, c.Field)
			}
		}
		pendingSections = pendingRestartSections(live, disk)
	}

	w.Header().Set("ETag", disk.Integrity.ConfigHash)
	writeJSON(w, map[string]interface{}{
		"section":          section,
		"values":           values,
		"etag":             disk.Integrity.ConfigHash,
		"pending_restart":  len(pendingFields) > 0,
		"pending_fields":   pendingFields,
		"pending_sections": pendingSections,
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
	disk.ConfigDir = s.cfg.ConfigDir
	if disk.Integrity.ConfigHash != ifMatch {
		writeJSONError(w, "config changed on disk, reload", http.StatusPreconditionFailed)
		return
	}
	if rejectIfConfDirChanged(w, s.cfg.ConfigDir, disk.Integrity.ConfdHash) {
		return
	}

	clone := cloneConfigForSettingsApply(disk)

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
	if section.ID == "firewall" {
		warnings = append(warnings, firewallLockoutWarnings(&clone)...)
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

	if err := integrity.SignAndSavePreserving(s.cfg.ConfigFile, s.cfg.ConfigDir, edited, &clone, disk.Integrity.BinaryHash); err != nil {
		writeJSONError(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newETag := clone.Integrity.ConfigHash
	newIntegrity := clone.Integrity

	if len(restartFields) == 0 {
		if live := config.Active(); live != nil {
			liveClone := cloneConfigForSettingsApply(live)
			if _, liveErrs := buildChangeSet(section, &liveClone, body.Changes); len(liveErrs) == 0 {
				liveClone.Integrity = newIntegrity
				config.SetActive(&liveClone)
			} else {
				livePatched := *live
				livePatched.Integrity = newIntegrity
				config.SetActive(&livePatched)
			}
		} else {
			config.SetActive(&clone)
		}
	} else if live := config.Active(); live != nil {
		livePatched := *live
		livePatched.Integrity = newIntegrity
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
		"pending_sections": pendingRestartSections(config.Active(), &clone),
		"warnings":         warnings,
		"new_etag":         newETag,
	})
}

func rejectIfConfDirChanged(w http.ResponseWriter, confDir, storedHash string) bool {
	currentHash, err := integrity.HashConfDir(confDir)
	if err != nil {
		writeJSONError(w, "hash conf.d: "+err.Error(), http.StatusInternalServerError)
		return true
	}
	if currentHash != storedHash {
		writeJSONError(w, "conf.d changed on disk, reload", http.StatusPreconditionFailed)
		return true
	}
	return false
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

		if field.Type == "[]enum" {
			if field.OptionsSource == "disabled_check_names" {
				var err error
				raw, err = normaliseDisabledCheckNamesRaw(raw)
				if err != nil {
					errs = append(errs, fieldError{Field: key, Message: "decode: " + err.Error()})
					continue
				}
			}
			if badValues, ok := validateEnumArray(field, raw); !ok {
				for _, bv := range badValues {
					errs = append(errs, fieldError{Field: key, Message: "unknown value: " + bv})
				}
				continue
			}
		}

		if field.Type == "enum" {
			if badValue, ok := validateEnumScalar(field, raw); !ok {
				errs = append(errs, fieldError{Field: key, Message: "unknown value: " + badValue})
				continue
			}
		}

		if field.Type == "[]int" {
			normalised, badValues, perr := normaliseIntArray(field, raw)
			if perr != nil {
				errs = append(errs, fieldError{Field: key, Message: perr.Error()})
				continue
			}
			if len(badValues) > 0 {
				for _, bv := range badValues {
					errs = append(errs, fieldError{Field: key, Message: "invalid value: " + bv})
				}
				continue
			}
			raw = normalised
		}

		// For float fields, coerce JSON string -> JSON number so the downstream
		// json.Unmarshal into *float64 (in applyToClone) succeeds.
		if field.Type == "float" {
			if normalised, ok := coerceFloatRaw(raw); ok {
				raw = normalised
			} else {
				errs = append(errs, fieldError{Field: key, Message: "decode: expected float"})
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

func validateEnumScalar(field *SettingsField, raw json.RawMessage) (bad string, ok bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "(not a string)", false
	}
	resolved := resolvedOptionsForField(field)
	if len(resolved) == 0 {
		return "", true
	}
	for _, opt := range resolved {
		if value == opt {
			return "", true
		}
	}
	return value, false
}

func normaliseDisabledCheckNamesRaw(raw json.RawMessage) (json.RawMessage, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("expected string array")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// validateEnumArray checks that raw is a JSON array of strings, each of
// which appears in the field's resolved Options. Returns the slice of
// unknown values and ok=false when any value is out-of-set. An empty
// array is allowed (clears the list). Calls resolveFieldOptions-style
// logic by inspecting OptionsSource + Options directly so validation
// doesn't depend on GET ordering.
func validateEnumArray(field *SettingsField, raw json.RawMessage) (bad []string, ok bool) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return []string{"(not a string array)"}, false
	}
	resolved := resolvedOptionsForField(field)
	if len(resolved) == 0 {
		return nil, true
	}
	allowed := make(map[string]struct{}, len(resolved))
	for _, v := range resolved {
		allowed[v] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		if _, okk := allowed[v]; !okk {
			bad = append(bad, v)
		}
	}
	return bad, len(bad) == 0
}

// resolvedOptionsForField returns the flat list of allowed values for a
// []enum field, whether it uses static Options or an OptionsSource. Keeps
// POST-side validation independent of the GET-time mutation.
func resolvedOptionsForField(field *SettingsField) []string {
	tmp := &SettingsField{Type: field.Type, OptionsSource: field.OptionsSource}
	switch field.OptionsSource {
	case "check_names":
		applyCheckNameOptions(tmp)
	case "disabled_check_names":
		// Validation accepts a wider set than the UI dropdown (which lists
		// public finding names only): the scheduler also honors compatibility
		// runner IDs, so rejecting them here would break existing configs.
		return disabledCheckValidationOptions()
	case "geoip_editions":
		applyGeoIPEditionOptions(tmp)
	}
	if len(tmp.Options) > 0 {
		return tmp.Options
	}
	if len(field.Options) > 0 {
		return field.Options
	}
	return tmp.Options
}

// firewallLockoutWarnings flags the most common ways a firewall save can lock
// the operator out: WebUI port missing from tcp_in (or tcp6_in when IPv6 dual
// stack is enabled), and firewall.enabled flipped on while the WebUI port is
// not allowed inbound. Returns warnings only -- never errors -- so the UI can
// surface a confirm modal without blocking deliberate changes.
func firewallLockoutWarnings(cfg *config.Config) []fieldError {
	if cfg == nil || cfg.Firewall == nil {
		return nil
	}
	listen := cfg.WebUI.Listen
	if listen == "" {
		listen = "0.0.0.0:9443"
	}
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	contains := func(ports []int, p int) bool {
		for _, q := range ports {
			if q == p {
				return true
			}
		}
		return false
	}
	var out []fieldError
	if !contains(cfg.Firewall.TCPIn, port) {
		out = append(out, fieldError{
			Field:   "tcp_in",
			Message: fmt.Sprintf("WebUI listens on %d but the port is not in tcp_in. Restart will lock you out of the WebUI.", port),
		})
	}
	if cfg.Firewall.IPv6 && len(cfg.Firewall.TCP6In) > 0 && !contains(cfg.Firewall.TCP6In, port) {
		out = append(out, fieldError{
			Field:   "tcp6_in",
			Message: fmt.Sprintf("IPv6 dual-stack is enabled and tcp6_in does not include WebUI port %d.", port),
		})
	}
	return out
}

// normaliseIntArray parses raw as a JSON array of integers (or strings that
// parse as integers), enforces field.Min/Max as the per-element bound (default
// 1..65535 for port-list semantics when both are nil), deduplicates, and
// returns a JSON array of distinct ascending integers. Returns the offending
// raw values as badValues when any element is outside the allowed range; the
// parse error path is reserved for malformed JSON.
func normaliseIntArray(field *SettingsField, raw json.RawMessage) (json.RawMessage, []string, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, nil, fmt.Errorf("expected array of ints: %s", err.Error())
	}
	minV := int64(1)
	maxV := int64(65535)
	if field.Min != nil {
		minV = *field.Min
	}
	if field.Max != nil {
		maxV = *field.Max
	}
	seen := make(map[int64]struct{}, len(items))
	out := make([]int64, 0, len(items))
	var bad []string
	for _, item := range items {
		var n int64
		if err := json.Unmarshal(item, &n); err != nil {
			var s string
			if serr := json.Unmarshal(item, &s); serr != nil {
				bad = append(bad, string(item))
				continue
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			parsed, perr := strconv.ParseInt(s, 10, 64)
			if perr != nil {
				bad = append(bad, s)
				continue
			}
			n = parsed
		}
		if n < minV || n > maxV {
			bad = append(bad, strconv.FormatInt(n, 10))
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(bad) > 0 {
		return nil, bad, nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, nil, err
	}
	return encoded, nil, nil
}

// coerceFloatRaw returns a JSON-number representation of raw if raw is either
// a JSON number already or a JSON string that parses to float64. The second
// return is false if neither form is valid.
func coerceFloatRaw(raw json.RawMessage) (json.RawMessage, bool) {
	var asNum float64
	if err := json.Unmarshal(raw, &asNum); err == nil {
		b, _ := json.Marshal(asNum)
		return b, true
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		f, err := strconv.ParseFloat(asStr, 64)
		if err != nil {
			return nil, false
		}
		b, _ := json.Marshal(f)
		return b, true
	}
	return nil, false
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
	if field.Type == "float" {
		// Accept either a JSON number or a JSON string containing a number.
		var asNum float64
		if err := json.Unmarshal(raw, &asNum); err == nil {
			return asNum, nil
		}
		var asStr string
		if err := json.Unmarshal(raw, &asStr); err == nil {
			f, perr := strconv.ParseFloat(asStr, 64)
			if perr != nil {
				return nil, fmt.Errorf("not a float: %q", asStr)
			}
			return f, nil
		}
		return nil, fmt.Errorf("expected float, got %s", string(raw))
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
		if v.Kind() == reflect.Pointer {
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

// settingsRestartDelay is how long the restart is deferred after the 202 is
// written, so the acknowledgement reaches the client before systemctl restart
// SIGTERMs this process. Overridden in tests to keep them fast.
var settingsRestartDelay = 250 * time.Millisecond

// apiSettingsRestart handles POST /api/v1/settings/restart. It schedules the
// restart asynchronously and returns 202 immediately: `systemctl restart csm`
// SIGTERMs this very process, so a synchronous restart cannot send a clean
// response -- the call returns "signal: terminated" and the old handler turned
// that into a spurious 500 even though the restart had succeeded. The frontend
// treats 202 as "restart issued" and polls for the daemon to return; a failed
// restart surfaces as the daemon not coming back, and the error is logged
// server-side by scheduleDaemonRestart.
func (s *Server) apiSettingsRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.auditLog(r, "settings-restart", "daemon", "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":           "restart issued",
		"started_at_token": s.daemonStartToken(),
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	s.scheduleDaemonRestart(settingsRestartDelay)
}

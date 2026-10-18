package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// ControllerListener is one bind_socket entry of the loaded controller
// worker. Raw is the entry as rspamd printed it, used as the finding key.
type ControllerListener struct {
	Raw      string
	Unix     bool
	Path     string
	Mode     fs.FileMode
	HostPort string
}

// ControllerConfig is the loaded controller worker. Password values never
// leave ParseControllerConfig; only whether each one is set.
type ControllerConfig struct {
	Present           bool
	Listeners         []ControllerListener
	TrustEntries      []string
	PasswordSet       bool
	EnablePasswordSet bool
}

// ParseControllerConfig reads the controller worker from the full
// `rspamadm configdump -j` output. Errors name the field, never a value.
func ParseControllerConfig(fullDump []byte) (ControllerConfig, error) {
	var cfg ControllerConfig
	root, err := dumpObjectAs[json.RawMessage](fullDump, "worker")
	if err != nil {
		return cfg, err
	}
	section, ok := root["worker"]
	if !ok {
		return cfg, nil
	}
	controller, err := controllerSection(section)
	if err != nil || controller == nil {
		return cfg, err
	}
	fields, err := dumpObjectAs[json.RawMessage](controller, "worker controller")
	if err != nil {
		return cfg, err
	}
	cfg.Present = true
	binds, err := stringOrList(fields, "bind_socket")
	if err != nil {
		return ControllerConfig{}, err
	}
	if len(binds) == 0 {
		return ControllerConfig{}, errors.New("configdump worker controller: bind_socket is missing")
	}
	for _, b := range binds {
		l, err := parseControllerBind(b)
		if err != nil {
			return ControllerConfig{}, err
		}
		cfg.Listeners = append(cfg.Listeners, l)
	}
	if cfg.TrustEntries, err = stringOrList(fields, "secure_ip"); err != nil {
		return ControllerConfig{}, err
	}
	if cfg.PasswordSet, err = passwordSet(fields, "password"); err != nil {
		return ControllerConfig{}, err
	}
	if cfg.EnablePasswordSet, err = passwordSet(fields, "enable_password"); err != nil {
		return ControllerConfig{}, err
	}
	return cfg, nil
}

// controllerSection returns the controller object from the worker section,
// which rspamd prints as a list of single-key objects (4.2) or as an object
// keyed by worker type.
func controllerSection(section json.RawMessage) (json.RawMessage, error) {
	var entries []json.RawMessage
	switch trimmed := bytes.TrimSpace(section); {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, errors.New("configdump worker: invalid JSON")
		}
	default:
		entries = []json.RawMessage{section}
	}
	var found json.RawMessage
	for _, entry := range entries {
		workers, err := dumpObjectAs[json.RawMessage](entry, "worker")
		if err != nil {
			return nil, err
		}
		c, ok := workers["controller"]
		if !ok {
			continue
		}
		if found != nil {
			return nil, errors.New("configdump worker: more than one controller worker")
		}
		found = c
	}
	return found, nil
}

func stringOrList(fields map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("configdump worker controller: %s is not a string or a list of strings", name)
	}
	return many, nil
}

func passwordSet(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok {
		return false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("configdump worker controller: %s is not a string", name)
	}
	return value != "", nil
}

// parseControllerBind splits "path option=value ..." for Unix sockets and
// keeps host:port forms whole. Only mode= matters for exposure.
func parseControllerBind(raw string) (ControllerListener, error) {
	l := ControllerListener{Raw: raw}
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return l, errors.New("configdump worker controller: empty bind_socket entry")
	}
	addr := parts[0]
	if !strings.HasPrefix(addr, "/") {
		if strings.Contains(addr, "/") || len(parts) > 1 {
			return l, errors.New("configdump worker controller: bind_socket entry is neither an absolute Unix path nor host:port")
		}
		l.HostPort = addr
		return l, nil
	}
	l.Unix, l.Path = true, filepath.Clean(addr)
	for _, opt := range parts[1:] {
		value, ok := strings.CutPrefix(opt, "mode=")
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(value, 8, 32)
		if err != nil || mode > 0o7777 {
			return l, errors.New("configdump worker controller: bind_socket mode is not an octal file mode")
		}
		l.Mode = fs.FileMode(mode)
	}
	return l, nil
}

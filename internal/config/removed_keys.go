package config

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"
)

// removedKeys are settings an earlier release documented and that nothing
// reads any more. Decoding is strict, so they are dropped before the decoder
// sees them: a host upgraded with one still in csm.yaml or a conf.d fragment
// keeps starting, and Validate warns so the operator can delete the key.
var removedKeys = []string{
	"alerts.webhook.per_finding",
	"thresholds.state_expiry_hours",
	"thresholds.wp_core_check_interval_min",
	"thresholds.webshell_scan_interval_min",
	"thresholds.filesystem_scan_interval_min",
	"email_protection.php_relay.reputation_failures_per_24h",
	"email_protection.php_relay.baseline_sigma",
	"email_protection.php_relay.baseline_observation_days",
	"email_protection.forward_guard.skip_forwarders",
}

// stripRemovedKeys returns data without any removed key and the dotted paths
// it dropped, in removedKeys order. Data without a removed key is returned
// unchanged, so the common case never re-encodes the document.
func stripRemovedKeys(data []byte) ([]byte, []string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return data, nil, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return data, nil, nil
	}
	var dropped []string
	for _, key := range removedKeys {
		if deleteMappingPath(doc.Content[0], strings.Split(key, ".")) {
			dropped = append(dropped, key)
		}
	}
	if len(dropped) == 0 {
		return data, nil, nil
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, nil, err
	}
	return out, dropped, nil
}

// deleteMappingPath removes the key at path from the mapping node and reports
// whether it was present.
func deleteMappingPath(node *yaml.Node, path []string) bool {
	if node == nil || node.Kind != yaml.MappingNode || len(path) == 0 {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			return true
		}
		return deleteMappingPath(node.Content[i+1], path[1:])
	}
	return false
}

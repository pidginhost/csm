// Package packaging carries the config file the packages install, so that
// `csm install` writes the same starting config with fresh credentials.
package packaging

import _ "embed"

// DefaultConfig is csm.yaml.default, installed as /etc/csm/csm.yaml.
//
//go:embed csm.yaml.default
var DefaultConfig []byte

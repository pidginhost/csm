// Package packaging carries the shared config template for package and CLI
// installs. The CLI fills credentials and retains its runtime policy defaults.
package packaging

import _ "embed"

// DefaultConfig is csm.yaml.default, installed as /etc/csm/csm.yaml.
//
//go:embed csm.yaml.default
var DefaultConfig []byte

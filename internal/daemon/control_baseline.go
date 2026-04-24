package daemon

import (
	"encoding/json"
	"fmt"
)

// handleBaseline is a stub. The real implementation lands in Task 3 of
// the phase-2 daemon-control-socket plan; it is wired into dispatch now
// so the CLI migration can compile against a command name that exists.
func (c *ControlListener) handleBaseline(_ json.RawMessage) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

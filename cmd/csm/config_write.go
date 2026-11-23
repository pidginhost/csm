package main

import (
	"fmt"
	"io"

	"github.com/pidginhost/csm/internal/integrity"
)

// runConfigWrite is `csm config-write`, the daemon's helper for saving a
// signed config: the daemon's own sandbox cannot write the config's
// directory, so it hands the signed result to this command, which runs in a
// transient unit that can.
func runConfigWrite(in io.Reader, errOut io.Writer) int {
	c, err := integrity.ReadSignedConfig(in)
	if err == nil {
		err = integrity.WriteSignedConfig(c)
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "config-write:", err)
		return 1
	}
	return 0
}

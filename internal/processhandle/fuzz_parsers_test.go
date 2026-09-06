//go:build linux

package processhandle

import (
	"fmt"
	"testing"
)

func FuzzProcStatState(f *testing.F) {
	f.Add("sleep", uint8(0))
	f.Add("name ) with spaces (", uint8(4))
	f.Add("line\nbreak))", uint8(6))
	f.Fuzz(func(t *testing.T, name string, index uint8) {
		const states = "RSDZTtXxKWPIN"
		state := states[int(index)%len(states)]
		data := []byte(fmt.Sprintf("42 (%s) %c 1 2 3\n", name, state))
		got, err := procStatState(data)
		if err != nil || got != state {
			t.Fatalf("state = %q, %v; want %q", got, err, state)
		}
		// Malformed records are also attacker-controlled parser inputs.
		_, _ = procStatState([]byte(name))
	})
}

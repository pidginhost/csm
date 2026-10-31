//go:build linux && yara

package yara

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Native rule memory is outside Go's heap. Check that the executable mappings
// allocated by deserialization disappear after the last Go reference is gone.
func TestLoadedRulesReleaseNativeMemory(t *testing.T) {
	compiled, err := CompileSources([]Source{{Name: "test.yar", Text: []byte("rule test { condition: true }")}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = compiled.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	executableMappings := func() map[string]bool {
		t.Helper()
		data, readErr := os.ReadFile("/proc/self/maps")
		if readErr != nil {
			t.Fatal(readErr)
		}
		out := make(map[string]bool)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 5 && strings.Contains(fields[1], "x") {
				out[fields[0]] = true
			}
		}
		return out
	}
	// Deserialization also initializes shared executable code. Establish the
	// baseline after releasing a warm-up set so only per-set mappings count.
	warm, err := LoadRules(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	warm.rules.Destroy()
	before := executableMappings()
	allocated := func() map[string]bool {
		var loaded []*Rules
		for range 8 {
			rules, err := LoadRules(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if rules.Count() != 1 {
				t.Fatal("loaded rule missing")
			}
			loaded = append(loaded, rules)
		}
		after := executableMappings()
		for mapping := range before {
			delete(after, mapping)
		}
		runtime.KeepAlive(loaded)
		return after
	}()
	if len(allocated) == 0 {
		t.Fatal("deserialization allocated no executable mappings to track")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		current := executableMappings()
		remaining := 0
		for mapping := range allocated {
			if current[mapping] {
				remaining++
			}
		}
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d native executable mappings remain after loaded rules were collected", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
	runtime.KeepAlive(compiled)
}

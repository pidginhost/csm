package modsec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

const overridesHeader = "# CSM ModSecurity Rule Overrides\n# Managed by CSM - do not edit manually.\n"

// WriteOverrides writes the overrides file with SecRuleRemoveById directives.
// Atomic write (tmp + rename). Sorts IDs for deterministic output.
func WriteOverrides(path string, disabledIDs []int) error {
	sort.Ints(disabledIDs)

	var sb strings.Builder
	sb.WriteString(overridesHeader)
	for _, id := range disabledIDs {
		fmt.Fprintf(&sb, "SecRuleRemoveById %d\n", id)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0640); err != nil {
		return fmt.Errorf("writing overrides tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming overrides: %w", err)
	}
	return nil
}

// ReadOverrides reads the overrides file and returns disabled rule IDs.
// Returns empty list (not error) if the file does not exist.
func ReadOverrides(path string) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var ids []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SecRuleRemoveById ") {
			idStr := strings.TrimPrefix(line, "SecRuleRemoveById ")
			if id, err := strconv.Atoi(strings.TrimSpace(idStr)); err == nil && id >= 900000 && id <= 900999 {
				ids = append(ids, id)
			}
		}
	}
	return ids, scanner.Err()
}

// ReadOverridesRaw reads the overrides file content for rollback purposes.
// Returns nil (not error) if the file does not exist.
func ReadOverridesRaw(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// RestoreOverrides writes raw content back to the overrides file (for rollback).
// Uses atomic tmp+rename to prevent partial writes on crash.
func RestoreOverrides(path string, content []byte) error {
	if content == nil {
		// File didn't exist before - remove it
		os.Remove(path)
		return nil
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0640); err != nil {
		return fmt.Errorf("writing rollback tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming rollback: %w", err)
	}
	return nil
}

// EnsureOverridesInclude appends an Include directive for the overrides file
// to a ModSecurity config file if not already present, and creates an empty
// overrides file if it doesn't exist. Idempotent: re-reads content under the
// write-open to avoid appending duplicate Include directives.
func EnsureOverridesInclude(rulesFile, overridesFile string) {
	// Open for read+write to check-then-append atomically (same fd).
	f, err := os.OpenFile(rulesFile, os.O_RDWR|os.O_APPEND, 0640)
	if err != nil {
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return
	}
	if !strings.Contains(string(data), overridesFile) {
		fmt.Fprintf(f, "\n# CSM overrides - managed by CSM rule management\nInclude %s\n", overridesFile)
	}

	// Create empty overrides file if it doesn't exist
	if _, err := os.Stat(overridesFile); os.IsNotExist(err) {
		_ = os.WriteFile(overridesFile, []byte(overridesHeader), 0640)
	}
}

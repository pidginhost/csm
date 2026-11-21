package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

func configDirFromArgs(args []string) (string, bool, error) {
	path := ""
	explicit := false
	for i, arg := range args {
		value, equals := strings.CutPrefix(arg, "--config-dir=")
		if !equals && arg != "--config-dir" {
			continue
		}
		if !equals {
			if i+1 >= len(args) {
				return "", true, fmt.Errorf("--config-dir requires a path")
			}
			value = args[i+1]
		}
		if value == "" {
			return "", true, fmt.Errorf("--config-dir requires a non-empty path")
		}
		path = value
		explicit = true
	}
	return path, explicit, nil
}

func validateConfDir(path string) (string, error) {
	return config.ValidateConfDir(path)
}

func resolveConfDirFromArgs(args []string) (string, error) {
	if path, explicit, err := configDirFromArgs(args); explicit || err != nil {
		if err != nil {
			return "", err
		}
		resolved, validateErr := validateConfDir(path)
		if validateErr != nil {
			return "", fmt.Errorf("--config-dir refused: %w", validateErr)
		}
		return resolved, nil
	}

	if v := os.Getenv("CSM_CONFIG_DIR"); v != "" {
		resolved, err := validateConfDir(v)
		if err != nil {
			return "", fmt.Errorf("CSM_CONFIG_DIR refused: %w", err)
		}
		return resolved, nil
	}
	return defaultConfDir, nil
}

// resolveConfDir returns the conf.d directory honoring --config-dir first,
// then CSM_CONFIG_DIR, then the packaged default.
func resolveConfDir() string {
	confDir, err := resolveConfDirFromArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return confDir
}

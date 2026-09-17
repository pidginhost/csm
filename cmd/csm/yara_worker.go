package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yaraworker"
)

func yaraWorkerConfig(args []string) (yaraworker.Config, *config.Config, error) {
	var cfg yaraworker.Config
	var inheritedDir *string
	var disabledSet, configDirSet, configPathSet bool
	fs := flag.NewFlagSet("yara-worker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.SocketPath, "socket", yaraworker.DefaultSocketPath(), "worker socket")
	fs.StringVar(&cfg.RulesDir, "rules-dir", "", "rules directory")
	configPath := fs.String("config", "", "configuration file")
	configDir := fs.String("config-dir", "", "configuration fragments")
	fs.Func("inherited-config-dir", "daemon-selected configuration fragments", func(value string) error {
		if value != "" && !filepath.IsAbs(value) {
			return fmt.Errorf("inherited config directory must be absolute")
		}
		inheritedDir = &value
		return nil
	})
	fs.Func("disabled-rules", "effective disabled rule names as JSON", func(value string) error {
		disabledSet = true
		return json.Unmarshal([]byte(value), &cfg.DisabledRules)
	})
	if err := fs.Parse(args); err != nil {
		return cfg, nil, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "config-dir" {
			configDirSet = true
		}
		if f.Name == "config" {
			configPathSet = true
		}
	})
	if configDirSet && inheritedDir != nil {
		return cfg, nil, fmt.Errorf("--config-dir and --inherited-config-dir cannot be combined")
	}
	if !configPathSet {
		path, _, err := resolveConfigPathFromArgs(nil)
		if err != nil {
			return cfg, nil, err
		}
		*configPath = path
	}
	confDir := ""
	if inheritedDir != nil {
		// The daemon has already selected this path. LoadWithDir tolerates
		// absence and still checks trust on existing directories/fragments.
		// Re-resolving defaults here could select unrelated config instead.
		confDir = *inheritedDir
	} else {
		var explicitArgs []string
		if configDirSet {
			explicitArgs = []string{"--config-dir", *configDir}
		}
		var err error
		confDir, err = resolveConfDirFromArgs(explicitArgs)
		if err != nil {
			return cfg, nil, err
		}
	}
	loaded, err := config.LoadWithDir(*configPath, confDir)
	if err != nil {
		return cfg, nil, err
	}
	if !disabledSet {
		cfg.DisabledRules = loaded.Signatures.DisabledRules
	}
	return cfg, loaded, nil
}

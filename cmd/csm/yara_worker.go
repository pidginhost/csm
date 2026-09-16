package main

import (
	"encoding/json"
	"flag"
	"io"

	"github.com/pidginhost/csm/internal/yaraworker"
)

func yaraWorkerConfig(args []string, disabled []string) (yaraworker.Config, error) {
	cfg := yaraworker.Config{DisabledRules: disabled}
	fs := flag.NewFlagSet("yara-worker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.SocketPath, "socket", yaraworker.DefaultSocketPath(), "worker socket")
	fs.StringVar(&cfg.RulesDir, "rules-dir", "", "rules directory")
	// These flags are consumed by loadConfigLite for telemetry and manual use.
	fs.String("config", "", "configuration file")
	fs.String("config-dir", "", "configuration fragments")
	fs.Func("disabled-rules", "effective disabled rule names as JSON", func(value string) error {
		return json.Unmarshal([]byte(value), &cfg.DisabledRules)
	})
	err := fs.Parse(args)
	return cfg, err
}

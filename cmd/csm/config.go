package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"gopkg.in/yaml.v3"
)

func runConfig() {
	if len(os.Args) < 3 {
		printConfigUsage()
		os.Exit(1)
	}

	switch os.Args[2] {
	case "show":
		configShow()
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", os.Args[2])
		printConfigUsage()
		os.Exit(1)
	}
}

func printConfigUsage() {
	fmt.Fprintf(os.Stderr, `csm config — configuration display

Usage: csm config <command>

Commands:
  show [--no-redact] [--json]   Display current config (secrets redacted by default)
`)
}

func configShow() {
	cfg := loadConfig()

	noRedact := false
	asJSON := false
	for _, arg := range os.Args[3:] {
		switch arg {
		case "--no-redact":
			noRedact = true
		case "--json":
			asJSON = true
		}
	}

	displayCfg := cfg
	if !noRedact {
		displayCfg = config.Redact(cfg)
	}

	if asJSON {
		// YAML->map->JSON pipeline to preserve snake_case keys
		// (Config has YAML tags but no JSON tags)
		yamlData, err := yaml.Marshal(displayCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
			os.Exit(1)
		}
		var m map[string]interface{}
		if err := yaml.Unmarshal(yamlData, &m); err != nil {
			fmt.Fprintf(os.Stderr, "Error converting config: %v\n", err)
			os.Exit(1)
		}
		jsonData, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
	} else {
		yamlData, err := yaml.Marshal(displayCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(yamlData))
	}
}

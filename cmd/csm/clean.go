package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func runClean() {
	if code := runCleanCommand(os.Args[2:], os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// runCleanCommand sends an .htaccess to the .htaccess cleaner and anything
// else to the PHP cleaner, for a preview and an apply alike. File names and
// content are tenant-controlled, so all output is escaped for the terminal.
func runCleanCommand(args []string, stderr io.Writer) int {
	words, cfgArgs, ok := responseConfigArgs(args)
	preview := slices.Contains(words, "--preview")
	words = slices.DeleteFunc(words, func(a string) bool { return a == "--preview" })
	if !ok || len(words) != 1 || strings.HasPrefix(words[0], "-") || words[0] == "" {
		fmt.Fprintln(stderr, "Usage: csm clean <path> [--preview]")
		return 1
	}
	path := words[0]
	_, name := filepath.Split(path)
	htaccess := name == ".htaccess"
	if htaccess {
		cfg, err := cleanConfig(cfgArgs)
		if err != nil {
			fmt.Fprintf(stderr, "Loading config: %s\n", checks.DisplayField(err.Error()))
			return 1
		}
		if cfg != nil {
			defer config.SetActive(config.Active())
			config.SetActive(cfg)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			fmt.Fprintln(stderr, checks.DisplayField(err.Error()))
			return 1
		}
		path = absolute
	}
	label := checks.DisplayField(path)
	switch {
	case preview:
		render := checks.PreviewCleanInfectedFile
		if htaccess {
			render = checks.PreviewCleanHtaccessFile
		}
		diff, err := render(path)
		if err != nil {
			fmt.Fprintf(stderr, "PREVIEW FAILED for %s: %s\n", label, checks.DisplayField(err.Error()))
			return 1
		}
		if _, err := fmt.Fprintf(stderr, "PREVIEW (no changes written; run without --preview to clean)\n%s", diff); err != nil {
			return 1
		}
	case htaccess:
		res := checks.CleanHtaccessFile(path)
		switch {
		case res.Success:
			fmt.Fprintf(stderr, "CLEANED %s\n  %s\n", label, checks.DisplayField(res.Description))
		case res.Refused:
			fmt.Fprintf(stderr, "REFUSED to clean %s: %s\n", label, checks.DisplayField(res.Error))
			return 1
		default:
			fmt.Fprintf(stderr, "FAILED to clean %s: %s\n", label, checks.DisplayField(res.Error))
			return 1
		}
	default:
		result := checks.CleanInfectedFile(path)
		fmt.Fprintln(stderr, checks.FormatCleanResult(result))
		if !result.Cleaned {
			return 1
		}
	}
	return 0
}

// responseConfigArgs separates config paths from action flags in either
// position. A missing path must never consume a preview or apply flag.
func responseConfigArgs(args []string) (words, cfgArgs []string, ok bool) {
	for i := 0; i < len(args); i++ {
		flag, value, inline := strings.Cut(args[i], "=")
		if flag != "--config" && flag != "--config-dir" {
			words = append(words, args[i])
			continue
		}
		if !inline {
			i++
			if i == len(args) {
				return nil, nil, false
			}
			value = args[i]
		}
		if value == "" || strings.HasPrefix(value, "-") {
			return nil, nil, false
		}
		cfgArgs = append(cfgArgs, flag, value)
	}
	return words, cfgArgs, true
}

func cleanConfig(args []string) (*config.Config, error) {
	path, explicit, err := resolveConfigPathFromArgs(args)
	if err != nil {
		return nil, err
	}
	dir, err := resolveConfDirFromArgs(args)
	if err != nil {
		return nil, err
	}
	if !explicit && len(args) == 0 {
		// Standalone clean also works on platform-detected account roots.
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	return config.LoadWithDirOptions(path, dir, secretFreeLoadOptions)
}

func runDBCleanOptionCommand(args []string, stderr io.Writer, clean func(string, string, bool) checks.DBCleanResult) int {
	var words []string
	preview := false
	for _, arg := range args {
		if arg == "--preview" || arg == "--dry-run" {
			preview = true
		} else {
			words = append(words, arg)
		}
	}
	if len(words) != 2 || strings.HasPrefix(words[0], "-") || strings.HasPrefix(words[1], "--") {
		fmt.Fprintln(stderr, "Usage: csm db-clean --option <account> <option_name> [--preview]")
		return 1
	}
	result := clean(words[0], words[1], preview)
	if _, err := fmt.Fprint(stderr, checks.FormatDBCleanResult(result)); err != nil || !result.Success {
		return 1
	}
	return 0
}

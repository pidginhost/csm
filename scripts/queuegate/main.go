// queuegate checks reviewed queue ownership and emits required execution tests.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
)

func decodeFile(root fs.FS, name string, target any) error {
	data, err := fs.ReadFile(root, name)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: multiple JSON values or trailing data", name)
	}
	return nil
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("queuegate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rootPath := flags.String("root", ".", "repository root")
	scanOnly := flags.Bool("scan", false, "list allocations without classifying them or proving coverage")
	manifestPath := flags.String("manifest", "scripts/queue-inventory.json", "reviewed manifest path relative to root")
	mode := flags.String("mode", "portable", "required test mode: portable or kernel")
	baselinePath := flags.String("base-required", "", "existing required test JSON path relative to root")
	outputPath := flags.String("required-out", "", "write required test JSON to this path instead of stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	root := os.DirFS(*rootPath)
	if *scanOnly {
		if *outputPath != "" || *baselinePath != "" {
			return fmt.Errorf("scan-only cannot emit execution requirements")
		}
		sites, err := scanSources(root)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sites)
	}
	var manifest queueManifest
	if err := decodeFile(root, *manifestPath, &manifest); err != nil {
		return err
	}
	evidence, err := validateManifest(root, manifest)
	if err != nil {
		return err
	}
	var baseline []requiredTest
	if *baselinePath != "" {
		if decodeErr := decodeFile(root, *baselinePath, &baseline); decodeErr != nil {
			return decodeErr
		}
	}
	required, err := requiredTests(evidence, baseline, *mode)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(required, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *outputPath == "" {
		_, err = stdout.Write(data)
		return err
	}
	if writeErr := os.WriteFile(*outputPath, data, 0o600); writeErr != nil {
		return writeErr
	}
	_, err = fmt.Fprintf(stdout, "Queue inventory validated: %d allocations, %d owners; %d %s tests required.\n", len(manifest.Allocations), len(manifest.Owners), len(required), *mode)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

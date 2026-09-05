package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/corpusgate"
)

func main() {
	manifestPath := flag.String("manifest", "scripts/clean-corpus/manifest.json", "pinned source manifest")
	cache := flag.String("cache", ".cache/clean-corpus-archives", "verified archive cache")
	destination := flag.String("destination", "", "new extraction directory")
	output := flag.String("output", "", "inventory output directory")
	flag.Parse()
	if err := run(*manifestPath, *cache, *destination, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(manifestPath, cache, destination, output string) error {
	if destination == "" || output == "" {
		return fmt.Errorf("destination and output are required")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest corpusgate.Manifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	rows, err := corpusgate.Prepare(context.Background(), manifest, cache, destination)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	if err := corpusgate.WriteJSON(filepath.Join(output, "manifest.json"), manifest); err != nil {
		return err
	}
	if err := corpusgate.WriteJSON(filepath.Join(output, "inventory.json"), rows); err != nil {
		return err
	}
	fmt.Printf("Verified and extracted %d files from %d pinned applications\n", len(rows), len(manifest.Sources))
	return nil
}

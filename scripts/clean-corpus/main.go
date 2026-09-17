package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/corpusgate"
)

func main() {
	manifestPath := flag.String("manifest", "scripts/clean-corpus/manifest.json", "pinned source manifest")
	cache := flag.String("cache", ".cache/clean-corpus-archives", "verified archive cache")
	destination := flag.String("destination", "", "new extraction directory")
	output := flag.String("output", "", "inventory output directory")
	flag.Parse()
	if err := run(*manifestPath, *cache, *destination, *output, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(manifestPath, cache, destination, output string, stdout io.Writer) error {
	if destination == "" || output == "" {
		return fmt.Errorf("destination and output are required")
	}
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- operator-supplied manifest path
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
	return writeSummary(stdout, manifest, len(rows))
}

// writeSummary reports which supported CMSs the corpus covers and which
// still lack clean-corpus evidence. A pending line records absent evidence,
// never a passing scan.
func writeSummary(w io.Writer, manifest corpusgate.Manifest, files int) error {
	sourced := map[string]bool{}
	for _, s := range manifest.Sources {
		sourced[s.CMS] = true
	}
	kinds := make([]string, 0, len(sourced))
	for k := range sourced {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	pending := append([]corpusgate.PendingCMS(nil), manifest.Pending...)
	sort.Slice(pending, func(i, j int) bool { return pending[i].CMS < pending[j].CMS })
	var b strings.Builder
	fmt.Fprintf(&b, "Verified and extracted %d files from %d pinned applications\n", files, len(manifest.Sources))
	fmt.Fprintf(&b, "sourced: %s\n", strings.Join(kinds, ", "))
	b.WriteString("pending (no clean-corpus evidence):\n")
	for _, p := range pending {
		fmt.Fprintf(&b, "  %s: %s\n", p.CMS, p.Reason)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

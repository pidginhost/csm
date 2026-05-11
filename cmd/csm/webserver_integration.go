package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/integration/webserver"
	"github.com/pidginhost/csm/internal/platform"
)

// runWebserverIntegration dispatches the install / upgrade / status /
// validate / remove subcommands. Output is operator-friendly by
// default; pass --json for machine-readable Result blobs (used by
// post-install / post-upgrade package hooks).
func runWebserverIntegration() {
	args := os.Args[2:]
	if len(args) == 0 {
		webserverIntegrationUsage(os.Stderr)
		os.Exit(2)
	}

	asJSON := false
	var verb string
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "-h", "--help":
			webserverIntegrationUsage(os.Stdout)
			os.Exit(0)
		default:
			if verb == "" {
				verb = a
			}
		}
	}
	if verb == "" {
		webserverIntegrationUsage(os.Stderr)
		os.Exit(2)
	}

	inst, err := webserver.New(platform.Detect())
	if err != nil {
		if errors.Is(err, webserver.ErrUnknownWebserver) {
			// Skipped (not failed) so package post-install hooks on
			// hosts with no detectable webserver exit 0 cleanly.
			res := webserver.Result{
				Action:  verb,
				Status:  "skipped",
				Message: err.Error(),
			}
			emitResult(asJSON, res)
			return
		}
		fmt.Fprintf(os.Stderr, "webserver-integration: %v\n", err)
		os.Exit(1)
	}

	var (
		res webserver.Result
		op  error
	)
	switch verb {
	case "install":
		res, op = inst.Install()
	case "upgrade":
		res, op = inst.Upgrade()
	case "status":
		res, op = inst.Status()
	case "validate":
		res, op = inst.Validate()
	case "remove":
		res, op = inst.Remove()
	default:
		fmt.Fprintf(os.Stderr, "webserver-integration: unknown verb %q\n", verb)
		webserverIntegrationUsage(os.Stderr)
		os.Exit(2)
	}

	emitResult(asJSON, res)
	if op != nil {
		os.Exit(1)
	}
}

func emitResult(asJSON bool, res webserver.Result) {
	if asJSON {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Printf("webserver-integration %s\n", res.Action)
	fmt.Printf("  status:    %s\n", res.Status)
	if res.Webserver != "" {
		fmt.Printf("  webserver: %s\n", res.Webserver)
	}
	if res.SnippetPath != "" {
		fmt.Printf("  snippet:   %s\n", res.SnippetPath)
	}
	if res.OnDiskVer > 0 || res.ShippedVer > 0 {
		fmt.Printf("  versions:  on-disk=%d shipped=%d\n", res.OnDiskVer, res.ShippedVer)
	}
	if res.Message != "" {
		fmt.Printf("  message:   %s\n", res.Message)
	}
}

func webserverIntegrationUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: csm webserver-integration <install|upgrade|status|validate|remove> [--json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  install   Write the webserver snippet, validate via configtest, reload on success.")
	fmt.Fprintln(w, "  upgrade   Same as install; idempotent re-apply that picks up shipped template bumps.")
	fmt.Fprintln(w, "  status    Print detected webserver, snippet version on disk vs shipped, drift.")
	fmt.Fprintln(w, "  validate  Run the webserver's configtest against current state. No writes.")
	fmt.Fprintln(w, "  remove    Delete the snippet, validate, reload. Refuses operator-edited files.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 success, 1 failure, 2 usage error.")
}

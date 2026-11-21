package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/config"
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

	if slices.Contains(args, "-h") || slices.Contains(args, "--help") {
		webserverIntegrationUsage(os.Stdout)
		os.Exit(0)
	}
	verb, peerLog, asJSON, ok := parseWebserverIntegrationArgs(args)
	if !ok {
		fmt.Fprintf(os.Stderr, "webserver-integration: unknown verb %q\n", strings.Join(args, " "))
		webserverIntegrationUsage(os.Stderr)
		os.Exit(2)
	}
	action := verb
	if peerLog {
		action = "peer-log " + verb
	}

	info := platform.Detect()
	inst, err := webserver.New(info, nil)
	if err != nil {
		if errors.Is(err, webserver.ErrUnknownWebserver) {
			// Skipped (not failed) so package post-install hooks on
			// hosts with no detectable webserver exit 0 cleanly.
			res := webserver.Result{
				Action:  action,
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
	if peerLog {
		// The peer log needs no challenge settings or CSM configuration.
		res, op = inst.RunPeerLog(verb)
	} else {
		res, op = runWebserverIntegrationWithConfig(inst, verb, tryLoadConfigLite)
	}

	emitResult(asJSON, res)
	if op != nil {
		os.Exit(1)
	}
}

// parseWebserverIntegrationArgs reads a challenge verb, or "peer-log" and a
// peer log verb, --json, and the --config and --config-dir flags every csm
// command reads. Other flags and extra words are usage errors.
func parseWebserverIntegrationArgs(args []string) (verb string, peerLog, asJSON, ok bool) {
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			asJSON = true
		case a == "--config" || a == "--config-dir":
			// Read again when the configuration loads; skip its value.
			if i++; i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return "", false, false, false
			}
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "--config-dir="):
			if _, value, _ := strings.Cut(a, "="); value == "" {
				return "", false, false, false
			}
		case strings.HasPrefix(a, "-"):
			return "", false, false, false
		default:
			words = append(words, a)
		}
	}
	switch {
	case len(words) == 0:
	case words[0] == "peer-log":
		if len(words) == 2 && slices.Contains([]string{"install", "status", "remove"}, words[1]) {
			return words[1], true, asJSON, true
		}
	case len(words) == 1 && validWebserverIntegrationVerb(words[0]):
		return words[0], false, asJSON, true
	}
	return "", false, false, false
}

func validWebserverIntegrationVerb(verb string) bool {
	switch verb {
	case "install", "upgrade", "status", "validate", "remove":
		return true
	default:
		return false
	}
}

// Config loading can fail before challenge installation; peer logging needs
// none of those settings and must still get its own result.
func runWebserverIntegrationWithConfig(inst *webserver.Installer, verb string, load func() (*config.Config, error)) (webserver.Result, error) {
	if verb == "install" || verb == "upgrade" {
		cfg, err := load()
		if err != nil {
			return webserver.Result{Action: verb, Webserver: inst.Handler.Kind(), Status: "fail", Message: err.Error()}, err
		}
		inst.Config = webserver.RenderConfigFromConfig(cfg)
		// Only explicit installation may rebuild the cPanel site includes.
		inst.RebuildSiteIncludes = true
	}
	return inst.Run(verb)
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
	if res.FollowUp != "" {
		fmt.Println()
		fmt.Println("Manual setup required:")
		for _, line := range strings.Split(res.FollowUp, "\n") {
			fmt.Println("  " + line)
		}
	}
	if p := res.PeerLog; p != nil {
		fmt.Println("web peer log")
		fmt.Printf("  status:    %s\n", p.Status)
		if p.SnippetPath != "" {
			fmt.Printf("  snippet:   %s\n", p.SnippetPath)
		}
		if p.Message != "" {
			fmt.Printf("  message:   %s\n", p.Message)
		}
	}
}

func webserverIntegrationUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: csm webserver-integration <install|upgrade|status|validate|remove> [--json]")
	fmt.Fprintln(w, "       csm webserver-integration peer-log <install|status|remove> [--json]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  install   Write the webserver snippet, validate via configtest, reload on success.")
	fmt.Fprintln(w, "  upgrade   Same as install; idempotent re-apply that picks up shipped template bumps.")
	fmt.Fprintln(w, "  status    Print detected webserver, snippet version on disk vs shipped, drift.")
	fmt.Fprintln(w, "  validate  Run the webserver's configtest against current state. No writes.")
	fmt.Fprintln(w, "  remove    Delete the snippet, validate, reload. Refuses operator-edited files.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  peer-log  Manage the web peer log CSM uses to verify client addresses on")
	fmt.Fprintln(w, "            Apache and cPanel LiteSpeed. upgrade refreshes an installed one.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 success, 1 failure, 2 usage error.")
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pidginhost/csm/internal/privops"
)

// runPrivileges prints the privileged-operation inventory: what CSM does that
// needs root or a capability, what each writes, and the key that stops it.
// It reads nothing from the host, so an operator can run it before installing.
func runPrivileges() {
	format := "text"
	for _, arg := range os.Args[2:] {
		switch arg {
		case "--json":
			format = "json"
		case "--markdown":
			format = "markdown"
		}
	}

	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(privops.Operations()); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot encode privileged-operation inventory: %v\n", err)
			os.Exit(1)
		}
	case "markdown":
		fmt.Print(privops.Markdown())
	default:
		printPrivilegesText(os.Stdout)
	}
}

func printPrivilegesText(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OPERATION\tNEEDS\tTRIGGER\tWRITES\tTURN IT OFF")
	for _, op := range privops.Operations() {
		privs := make([]string, 0, len(op.Privileges))
		for _, p := range op.Privileges {
			privs = append(privs, string(p))
		}
		writes := "-"
		if len(op.Writes) > 0 {
			writes = strings.Join(op.Writes, " ")
		}
		if op.Unsandboxed {
			writes += " (unsandboxed)"
		}
		off := "-"
		switch {
		case op.DisableKey != "":
			off = op.DisableKey + ": " + op.DisableValue
		case op.Trigger == privops.Operator:
			off = "do not run the command"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", op.ID, strings.Join(privs, ","), op.Trigger, writes, off)
	}
	_ = tw.Flush()
}

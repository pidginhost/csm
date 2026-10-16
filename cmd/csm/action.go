package main

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/control"
)

// runAction reads one admission ledger record through the daemon: `csm
// action show <id>` takes a candidate ID or the action_id of an admission
// record and prints the candidate with its attempts as JSON.
func runAction() {
	if len(os.Args) != 4 || os.Args[2] != "show" {
		fmt.Fprintln(os.Stderr, "usage: csm action show <candidate-or-action-id>")
		os.Exit(1)
	}
	raw, err := sendControl(control.CmdActionShow, control.ActionShowArgs{ID: os.Args[3]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "action show: %v\n", err)
		os.Exit(1)
	}
	printJSON(raw)
}

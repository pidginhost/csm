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

	var err error
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(privops.Operations())
	case "markdown":
		_, err = fmt.Fprint(os.Stdout, privops.Markdown())
	default:
		err = printPrivilegesText(os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write privileged-operation inventory: %v\n", err)
		os.Exit(1)
	}
}

func printPrivilegesText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "OPERATION\tNEEDS\tTRIGGER\tWRITES\tTURN IT OFF"); err != nil {
		return err
	}
	for _, op := range privops.Operations() {
		privs := make([]string, 0, len(op.Privileges))
		for _, p := range op.Privileges {
			privs = append(privs, string(p))
		}
		stop := op.DisableInstruction()
		if op.DisableReason != "" {
			// The explanation is a sentence, not a cell. Keeping it in the
			// column would pad every other row to its length, so the row says
			// there is no switch and the line under it says why.
			stop = "not configurable"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			op.ID,
			clampCell(strings.Join(privs, ","), needsWidth),
			op.Trigger,
			clampCell(summarizeWrites(op.Writes, op.Unsandboxed), writesWidth),
			stop,
		); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return printPrivilegesNotes(w)
}

// printPrivilegesNotes explains the operations the table marks as having no
// config switch. The explanations are sentences, so they go under the table
// rather than in a column that would pad every row to their length.
func printPrivilegesNotes(w io.Writer) error {
	var notes []privops.Op
	for _, op := range privops.Operations() {
		if op.DisableReason != "" {
			notes = append(notes, op)
		}
	}
	if len(notes) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nOperations with no config switch:"); err != nil {
		return err
	}
	for _, op := range notes {
		if _, err := fmt.Fprintf(w, "  %s: %s\n", op.ID, op.DisableInstruction()); err != nil {
			return err
		}
	}
	return nil
}

// Column budgets for the terminal table. tabwriter pads every row to the
// widest cell, so one operation with a long privilege list or thirty write
// paths would otherwise push every other row off the screen. --json and
// --markdown carry the untruncated values.
//
// The config key is never clamped: it is what the operator has to type, and a
// truncated key is worse than a wide row.
const (
	writesShown = 2
	needsWidth  = 22
	writesWidth = 34
)

// clampCell shortens a cell to width, marking that it was cut.
func clampCell(value string, width int) string {
	if len(value) <= width {
		return value
	}
	return value[:width-1] + "\u2026"
}

// summarizeWrites renders the writes column for the terminal. --json and
// --markdown carry the complete list.
func summarizeWrites(writes []string, unsandboxed bool) string {
	out := "-"
	if len(writes) > 0 {
		shown := writes
		if len(shown) > writesShown {
			shown = shown[:writesShown]
		}
		out = strings.Join(shown, " ")
		if extra := len(writes) - len(shown); extra > 0 {
			out += fmt.Sprintf(" +%d more", extra)
		}
	}
	if unsandboxed {
		out += " (unsandboxed)"
	}
	return out
}

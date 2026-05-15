package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/control"
)

func runIncidents() {
	if len(os.Args) < 3 {
		printIncidentsUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "list":
		incidentsList()
	case "show":
		incidentsShow()
	case "status":
		incidentsStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown incidents subcommand: %s\n", os.Args[2])
		printIncidentsUsage()
		os.Exit(1)
	}
}

func printIncidentsUsage() {
	fmt.Fprintln(os.Stderr, `csm incidents - manage correlated security incidents

Usage:
  csm incidents list [--status all|active|open|contained|resolved|dismissed] [--limit N] [--offset N] [--all]
                                        List incidents newest first. Defaults to the first 100.
  csm incidents show <id>               Show one incident.
  csm incidents status <id> <state> [details]
                                        Set status: open, contained, resolved, dismissed.`)
}

func incidentsList() {
	fs := flag.NewFlagSet("csm incidents list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	status := fs.String("status", "all", "incident status filter: all, active, open, contained, resolved, dismissed")
	limit := fs.Int("limit", 100, "maximum incidents to return")
	offset := fs.Int("offset", 0, "starting offset")
	all := fs.Bool("all", false, "return every matching incident")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: csm incidents list [--status all|active|open|contained|resolved|dismissed] [--limit N] [--offset N] [--all]")
	}
	if err := fs.Parse(os.Args[3:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	raw, err := sendControl(control.CmdIncidentsList, control.IncidentListArgs{
		Limit:  *limit,
		Offset: *offset,
		Status: *status,
		All:    *all,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "incidents list: %v\n", err)
		os.Exit(1)
	}
	printJSON(raw)
}

func incidentsShow() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: csm incidents show <id>")
		os.Exit(1)
	}
	raw, err := sendControl(control.CmdIncidentsShow, control.IncidentShowArgs{ID: os.Args[3]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "incidents show: %v\n", err)
		os.Exit(1)
	}
	printJSON(raw)
}

func incidentsStatus() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: csm incidents status <id> <open|contained|resolved|dismissed> [details]")
		os.Exit(1)
	}
	details := ""
	if len(os.Args) >= 6 {
		details = os.Args[5]
	}
	raw, err := sendControl(control.CmdIncidentsStatus, control.IncidentStatusArgs{
		ID:      os.Args[3],
		Status:  os.Args[4],
		Details: details,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "incidents status: %v\n", err)
		os.Exit(1)
	}
	printJSON(raw)
}

// printJSON pretty-prints raw control-socket JSON. Extracted here so
// the three incidents commands stay compact; falls back to raw bytes
// when the payload is already human-readable (e.g. a bare "ok").
func printJSON(raw json.RawMessage) {
	var pretty interface{}
	if err := json.Unmarshal(raw, &pretty); err != nil {
		fmt.Println(string(raw))
		return
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		fmt.Println(string(raw))
		return
	}
	fmt.Println(string(out))
}

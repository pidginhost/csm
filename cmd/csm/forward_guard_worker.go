package main

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/mailfwd/adapter"
)

func runForwardGuardWorker() {
	if os.Geteuid() != 0 || len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "forward-guard worker requires root and reads one request from stdin")
		os.Exit(1)
	}
	if err := adapter.HandleEximMutation(os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

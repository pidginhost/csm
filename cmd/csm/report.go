package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// runReport handles the `csm report` subcommands for abuse reporting.
func runReport() {
	code := runReportArgs(os.Args[2:], os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func runReportArgs(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		reportUsage(errOut)
		return 2
	}
	switch args[0] {
	case "enroll", "keygen":
		if len(args) != 1 {
			reportUsage(errOut)
			return 2
		}
		return reportEnroll(out, errOut)
	case "--help", "-h", "help":
		reportUsage(errOut)
		return 0
	default:
		reportUsage(errOut)
		return 2
	}
}

func reportUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: csm report enroll")
	fmt.Fprintln(w, "  enroll   Generate an Ed25519 node key pair for abuse reporting.")
}

// reportEnroll generates a node key pair. The private key (hex) goes in the
// env var named by reputation.report.targets[].key_env; the public key is
// registered with the central abuse database operator, who issues a node id.
func reportEnroll(out, errOut io.Writer) int {
	privHex, pubHex, err := generateNodeKeyHex()
	if err != nil {
		fmt.Fprintf(errOut, "report enroll: key generation failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "Abuse-reporting node key pair generated.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "private key (store in the environment variable named by the target's key_env, keep secret):\n  %s\n", privHex)
	fmt.Fprintf(out, "public key (give to the central operator to enroll this node):\n  %s\n", pubHex)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "The operator approves the node and returns a node_id and key_id for the config.")
	return 0
}

// generateNodeKeyHex returns a fresh Ed25519 key pair as hex: the 64-byte
// private key and the 32-byte public key.
func generateNodeKeyHex() (privHex, pubHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

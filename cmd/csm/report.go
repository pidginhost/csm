package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// runReport handles the `csm report` subcommands for abuse reporting.
func runReport() {
	if len(os.Args) < 3 {
		reportUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "enroll", "keygen":
		reportEnroll()
	default:
		reportUsage()
		os.Exit(1)
	}
}

func reportUsage() {
	fmt.Fprintln(os.Stderr, "Usage: csm report enroll")
	fmt.Fprintln(os.Stderr, "  enroll   Generate an Ed25519 node key pair for abuse reporting.")
}

// reportEnroll generates a node key pair. The private key (hex) goes in the
// env var named by reputation.report.targets[].key_env; the public key is
// registered with the central abuse database operator, who issues a node id.
func reportEnroll() {
	privHex, pubHex, err := generateNodeKeyHex()
	if err != nil {
		fmt.Fprintf(os.Stderr, "report enroll: key generation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Abuse-reporting node key pair generated.")
	fmt.Println()
	fmt.Printf("private key (set as the target's key_env, keep secret):\n  %s\n", privHex)
	fmt.Printf("public key (give to the central operator to enroll this node):\n  %s\n", pubHex)
	fmt.Println()
	fmt.Println("The operator approves the node and returns a node_id and key_id for the config.")
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

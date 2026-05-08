package daemon

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// BPFEnforcementPolicy is the userspace-derived state to be loaded into
// the BPF policy + protected_ports + safe_uids maps. Pure data; no IO.
type BPFEnforcementPolicy struct {
	Enforce uint32
	DryRun  uint32
	Ports   []uint16
}

// BuildBPFEnforcementPolicy translates config into the policy struct
// the BPF program consumes. Disabled config returns zero policy
// (Enforce=0); the in-kernel program then short-circuits to allow.
func BuildBPFEnforcementPolicy(cfg *config.Config) BPFEnforcementPolicy {
	if cfg == nil || !cfg.BPFEnforcement.Enabled {
		return BPFEnforcementPolicy{}
	}
	if !connectionTrackerAllowsBPF(cfg) {
		return BPFEnforcementPolicy{}
	}
	p := BPFEnforcementPolicy{Enforce: 1}
	if cfg.BPFEnforcementDryRunEnabled() {
		p.DryRun = 1
	}
	if cfg.BPFEnforcement.DirectSMTPEgress && checks.DirectSMTPEgressBackendEnabled(cfg, "bpf") {
		for _, port := range cfg.Detection.DirectSMTPEgress.Ports {
			if port > 0 && port <= 65535 {
				p.Ports = append(p.Ports, uint16(port))
			}
		}
	}
	if len(p.Ports) == 0 {
		return BPFEnforcementPolicy{}
	}
	return p
}

func connectionTrackerAllowsBPF(cfg *config.Config) bool {
	switch strings.ToLower(strings.TrimSpace(cfg.Detection.ConnectionTrackerBackend)) {
	case "", "auto", "bpf":
		return true
	default:
		return false
	}
}

// safeUIDsFromPasswd returns a map of UIDs that should be exempt from
// in-kernel deny: UID 0 (root), UIDs <1000 (system accounts), and any
// platform-known MTA users that happen to live above 1000 on some
// distros. Hosted account UIDs (>=1000) are NOT in the safe map; their
// connections will be evaluated by the in-kernel deny path when
// enforcement is active.
//
// Caller passes a /etc/passwd path; production wiring uses /etc/passwd.
func safeUIDsFromPasswd(path string) (map[uint32]bool, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-controlled; production passes /etc/passwd
	if err != nil {
		return nil, err
	}
	defer f.Close()

	mta := platform.LocalMTAIdentities(platform.Detect())
	out := map[uint32]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		uid64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		uid := uint32(uid64)
		// UID 0 always safe.
		if uid == 0 {
			out[uid] = true
			continue
		}
		// System UIDs (<1000): always safe. Daemons, services,
		// distro-managed users.
		if uid < 1000 {
			out[uid] = true
			continue
		}
		// Hosted UIDs (>=1000): NOT safe by default. Exception:
		// platform-known MTA users on distros that put them above 1000.
		if mta.IsMTAUser(user) {
			out[uid] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

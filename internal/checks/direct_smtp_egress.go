package checks

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/processctx"
)

// DirectSMTPEgressInput is the input to the pure evaluator. The caller
// (BPF connection consumer or legacy poller) builds it from the live
// event and passes the platform-resolved MTA allowlist as MTA.
//
// Process is optional; when present the resulting finding includes the
// full process-ancestry tree. UID/User/PID/Comm/Exe are the live event
// fields and are used for sound classification.
type DirectSMTPEgressInput struct {
	UID     uint32
	User    string
	PID     uint32
	Comm    string
	Exe     string
	DstIP   net.IP
	DstPort uint16
	MTA     platform.MTAIdents
	Process *processctx.ProcessContext
	// Domain is an optional rDNS-resolved name for DstIP. When set, it
	// is included in the finding details. Populating it is the caller's
	// responsibility (off-path enrichment lands in Task 6).
	Domain string
}

// EvaluateDirectSMTPEgress returns a populated finding when the input
// represents a non-MTA local process opening an outbound SMTP connection.
// Pure function: no IO, no clock. Detector-disabled config returns
// (zero, false) without inspecting the input.
func EvaluateDirectSMTPEgress(cfg *config.Config, in DirectSMTPEgressInput) (alert.Finding, bool) {
	if cfg == nil || !cfg.Detection.DirectSMTPEgress.Enabled {
		return alert.Finding{}, false
	}
	if in.UID == 0 {
		return alert.Finding{}, false
	}
	if in.DstIP == nil || in.DstIP.IsLoopback() || in.DstIP.IsUnspecified() {
		return alert.Finding{}, false
	}
	if !portInList(in.DstPort, cfg.Detection.DirectSMTPEgress.Ports) {
		return alert.Finding{}, false
	}
	if isInfraIP(in.DstIP.String(), cfg.InfraIPs) {
		return alert.Finding{}, false
	}
	if in.MTA.IsMTAUser(in.User) {
		return alert.Finding{}, false
	}
	if in.Comm != "" && in.MTA.IsMTAProcess(in.Comm) {
		return alert.Finding{}, false
	}
	if in.Exe != "" && in.MTA.IsMTAProcess(filepath.Base(in.Exe)) {
		return alert.Finding{}, false
	}

	dst := in.DstIP.String()
	if in.DstIP.To4() == nil {
		dst = "[" + dst + "]"
	}
	details := fmt.Sprintf("UID: %d (%s), Process: %s, PID: %d, Destination: %s:%d",
		in.UID, in.User, in.Comm, in.PID, dst, in.DstPort)
	if in.Domain != "" {
		details += ", Domain: " + in.Domain
	}
	return alert.Finding{
		Severity: alert.High,
		Check:    "direct_smtp_egress",
		Message:  fmt.Sprintf("Non-MTA process opened outbound SMTP connection to %s:%d", dst, in.DstPort),
		Details:  details,
		Process:  in.Process,
	}, true
}

func portInList(p uint16, list []int) bool {
	for _, q := range list {
		// #nosec G115 -- list values come from operator YAML and are
		// bounded by uint16 in practice; port numbers above 65535 are
		// invalid TCP/UDP ports and silently won't match.
		if uint16(q) == p {
			return true
		}
	}
	return false
}

package health

import (
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/maillog"
)

// Capabilities is the static list of features this build supports. Phpanel
// reads it via /api/v1/capabilities to feature-detect without version
// sniffing. Add a string here when shipping a feature; remove when ripping
// one out. Keep the base order stable; build-tag gated capabilities are
// appended only when this binary actually supports them.
//
// BPF capability strings (`bpf-...`) are appended dynamically based on the
// running kernel's accepted BPF program types. Their presence depends on
// build tag and host kernel and is therefore not stable across deployments.
func Capabilities() []string {
	caps := []string{
		"confd.dropins.v1",          // P1
		"profile.phpanel-agent.v1",  // P1
		"status.json.v1",            // P2
		"capabilities.v1",           // P2
		"doctor.v1",                 // P2
		"config.schema.v1",          // P2
		"sd_notify.ready",           // P2
		"audit.fields.tenant.v1",    // P3
		"webhook.phpanel.v1",        // P3
		"events.sse.v1",             // P3
		"token.scope.readonly.v1",   // P3
		"mail.brute.account_key.v1", // P4
		"ti.source.rspamd.v1",       // P4
		"auto_response.dry_run.v1",  // P5
		"infra_ips.guard.v1",        // P5
		"store.backup.v1",           // P5
		"ti.source.upstream.v1",     // P6
		"verdict.callback.v1",       // P7
		"systemd.dropin.example.v1", // P7
		"incidents.v1",
		"bpf_enforcement.available.v1",
		"webui.prefs.v1",       // operator preferences + saved views
		"webui.undo.v1",        // bulk-action undo
		"mail.filter.exfil.v1", // BEC mail-filter exfiltration detection
		"mail.queue.composition.v1",
		"mail.forward_guard.v1",          // opt-in MTA-native forward-guard (hold spam/backscatter forward copies)
		"detect.http_scanner_profile.v1", // URL scanner-profile detector + challenge/block action
		"challenge.stats.v1",
		"verified_bots.editor.v1",   // operator-managed verified-bot allowlist (rDNS + IP ranges) with web editor
		"status.firewall_health.v1", // status snapshot reports firewall enabled/managed state + block counts
	}
	if maillog.JournalSupported() {
		caps = append(caps, "mail.source.journal.v1")
	}
	caps = appendBPFCaps(caps)
	caps = appendActiveBPFFeatures(caps)
	return caps
}

// appendActiveBPFFeatures adds one capability string per BPF-backed live
// monitor that is currently running on the kernel-side path (as opposed to
// its userspace fallback). Phases 2-4 extend this with their own feature
// keys; the test for each phase asserts the expected toggling.
func appendActiveBPFFeatures(out []string) []string {
	if bpf.ActiveKind("connection_tracker") == bpf.BackendBPF {
		out = append(out, "bpf-connection-tracker")
	}
	if bpf.ActiveKind("af_alg") == bpf.BackendBPF {
		out = append(out, "bpf-af-alg-live")
	}
	if bpf.ActiveKind("exec_monitor") == bpf.BackendBPF {
		out = append(out, "bpf-exec-monitor")
	}
	if bpf.ActiveKind("sensitive_files") == bpf.BackendBPF {
		out = append(out, "bpf-sensitive-files")
	}
	return out
}

// bpfCapabilities returns the cached probe result. Tests use this to assert
// that capability strings stay in sync with the shared BPF probe.
func bpfCapabilities() bpf.Capabilities { return bpf.Probe() }

// appendBPFCaps adds one capability string per BPF program type the kernel
// accepts. Phases 1-4 add a second helper alongside this one for per-feature
// "live monitor is currently running on BPF" strings.
func appendBPFCaps(out []string) []string {
	caps := bpf.Probe()
	if caps.LSMAttach {
		out = append(out, "bpf-lsm-attach")
	}
	if caps.CgroupSock {
		out = append(out, "bpf-cgroup-sock")
	}
	if caps.Tracepoint {
		out = append(out, "bpf-tracepoint")
	}
	if caps.Ringbuf {
		out = append(out, "bpf-ringbuf")
	}
	return out
}

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/verdict"
)

func applyBPFEnforcementVerdict(ctx context.Context, cfg *config.Config, ev ConnectionEvent, f *alert.Finding) {
	if cfg == nil || f == nil || !cfg.BPFEnforcement.VerdictCallback || !cfg.AutoResponse.VerdictCallback.Enabled {
		return
	}
	if ev.Decision != 1 && ev.Decision != 2 {
		return
	}
	vcCfg := cfg.AutoResponse.VerdictCallback
	vc := verdict.New(verdict.Config{
		URL:           vcCfg.URL,
		HMACSecret:    vcCfg.HMACSecret,
		HMACSecretEnv: vcCfg.HMACSecretEnv,
		Timeout:       time.Duration(vcCfg.TimeoutSec) * time.Second,
	})
	resp, err := vc.Ask(ctx, verdict.Request{
		IP:       ev.DstIP.String(),
		Reason:   fmt.Sprintf("bpf_enforcement:%s:%d", f.Check, ev.DstPort),
		Severity: f.Severity.String(),
		Source:   "bpf_enforcement",
	})
	if err != nil {
		csmlog.Warn("bpf enforcement verdict callback failed", "err", err, "dst", ev.DstIP.String())
		return
	}
	if resp.TenantID != "" && f.TenantID == "" {
		f.TenantID = resp.TenantID
	}
	if resp.Verdict != "" {
		appendFindingDetail(f, "Verdict callback: "+resp.Verdict)
	}
	if resp.TenantID != "" {
		appendFindingDetail(f, "Verdict tenant: "+resp.TenantID)
	}
	if resp.Note != "" {
		appendFindingDetail(f, "Verdict note: "+resp.Note)
	}
}

func appendFindingDetail(f *alert.Finding, detail string) {
	if detail == "" {
		return
	}
	if f.Details == "" {
		f.Details = detail
		return
	}
	f.Details += ", " + detail
}

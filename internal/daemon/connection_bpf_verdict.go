package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/verdict"
)

var errBPFVerdictDisabled = errors.New("verdict callback not configured")

// bpfVerdictEnabled reports whether this event is one the operator's callback
// should be asked about. Cheap enough for the ring-buffer consumer loop; the
// request itself is not, and runs on the enricher's workers.
func bpfVerdictEnabled(cfg *config.Config, ev ConnectionEvent) bool {
	if cfg == nil || !cfg.BPFEnforcement.VerdictCallback || !cfg.AutoResponse.VerdictCallback.Enabled {
		return false
	}
	return ev.Decision == 1 || ev.Decision == 2
}

// askBPFVerdict performs one callback. The client is built per call from the
// live configuration so a hot reload of the URL or secret is honoured.
func askBPFVerdict(ctx context.Context, cfg *config.Config, req verdict.Request) (verdict.Response, error) {
	if cfg == nil {
		return verdict.Response{}, errBPFVerdictDisabled
	}
	vcCfg := cfg.AutoResponse.VerdictCallback
	vc := verdict.New(verdict.Config{
		URL:                      vcCfg.URL,
		HMACSecret:               vcCfg.HMACSecret,
		HMACSecretEnv:            vcCfg.HMACSecretEnv,
		RequireResponseSignature: vcCfg.RequireResponseSignature,
		AllowUnsigned:            vcCfg.AllowUnsigned,
		Timeout:                  time.Duration(vcCfg.TimeoutSec) * time.Second,
	})
	return vc.Ask(ctx, req)
}

// bpfVerdictReason is the callback's reason string for one event.
func bpfVerdictReason(check string, port uint16) string {
	return fmt.Sprintf("bpf_enforcement:%s:%d", check, port)
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

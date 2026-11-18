package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/ipmap"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

const (
	stalwartCheckAddressList = "stalwart_address_list"
	stalwartCheckFilterOff   = "stalwart_spam_filter_off"
	stalwartListTickLimit    = 5 * time.Minute
)

// stalwartListState is what the last address list tick learned. ruleOff and
// filterOff are true only when Stalwart said so.
type stalwartListState struct {
	m                  *ipmap.Map
	filterOff, ruleOff bool
}

// startStalwartAddressList keeps CSM's address list in Stalwart's lookup
// lists, at start and every 10 minutes.
func (d *Daemon) startStalwartAddressList() {
	ctx := d.scanContext()
	d.wg.Add(1)
	obs.Go("stalwart-address-list", func() {
		defer d.wg.Done()
		ticker := time.NewTicker(antispamIPMapInterval)
		defer ticker.Stop()
		for {
			tickCtx, cancel := context.WithTimeout(ctx, stalwartListTickLimit)
			d.stalwartListTick(tickCtx, time.Now())
			cancel()
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
			}
		}
	})
}

// stalwartListTick builds the list, records what Stalwart says about its
// filter and rule, syncs the keys and settles both findings.
func (d *Daemon) stalwartListTick(ctx context.Context, now time.Time) []alert.Finding {
	cfg := d.currentCfg()
	m := ipmap.Build(ipmapSources(now, d.antispamInfraIPs(cfg)))
	st := &stalwartListState{m: &m}
	api, findings := stalwartListRead(ctx, cfg, st, now)
	if s := d.stalwart; s != nil {
		s.list.Store(st)
	}
	// Observe mode reads but leaves Stalwart's lookup lists as they are.
	if api != nil && !cfg.ObserveMode() {
		want := m.StalwartKeys()
		if st.ruleOff {
			want = nil
		}
		if _, err := syncStalwartKeys(ctx, api, want); err != nil {
			findings = append(findings, stalwartListFinding(err, now))
		}
	}
	// A timed-out tick still reports; only shutdown leaves findings as they are.
	if !errors.Is(ctx.Err(), context.Canceled) {
		owned := []string{stalwartCheckAddressList, stalwartCheckFilterOff}
		d.store.RearmAbsentDedupFindings(owned, findings)
		d.processScanFindings(cfg, findings, owned, "stalwart")
	}
	return findings
}

// stalwartListRead fills st from Stalwart. It returns the client only when
// the rule was read, so the keys can be synced.
func stalwartListRead(ctx context.Context, cfg *config.Config, st *stalwartListState, now time.Time) (stalwartAPI, []alert.Finding) {
	// Without a key setup and doctor report what is missing.
	if !stalwartKeyPresent(cfg) {
		return nil, nil
	}
	api, err := stalwartClient(cfg)
	if err != nil {
		return nil, []alert.Finding{stalwartListFinding(err, now)}
	}
	var findings []alert.Finding
	if stalwartFilterOff(ctx, api) {
		st.filterOff = true
		findings = append(findings, alert.Finding{
			Severity: alert.Warning, Check: stalwartCheckFilterOff, DedupKey: "filter_off",
			Message:   "Stalwart's spam filter is off",
			Details:   "Stalwart does not score incoming mail, so CSM's address list adds no score. Switch the spam filter on in Stalwart.",
			Timestamp: now,
		})
	}
	rule, found, err := api.SpamRule(ctx, stalwartsetup.AddressListRule)
	if err != nil {
		return nil, append(findings, stalwartListFinding(err, now))
	}
	st.ruleOff = !found || rule.Type != "Any" || !rule.Enabled
	return api, findings
}

// stalwartFilterOff reports whether Stalwart says its spam filter is off. A
// setting it cannot read leaves the filter not known off.
func stalwartFilterOff(ctx context.Context, api stalwartAPI) bool {
	if s, err := api.SpamSettings(ctx); err == nil && !s.Enabled {
		return true
	}
	off, err := api.SpamFilterStageOff(ctx)
	return err == nil && off
}

func stalwartListFinding(err error, now time.Time) alert.Finding {
	msg := "CSM cannot keep its address list in Stalwart up to date"
	if errors.Is(err, stalwartapi.ErrForbidden) {
		msg = "Stalwart refused CSM's key access to the address list; run csm stalwart setup"
	}
	return alert.Finding{
		Severity: alert.Warning, Check: stalwartCheckAddressList, DedupKey: "address_list",
		Message: msg, Details: err.Error(), Timestamp: now,
	}
}

// syncStalwartKeys makes each CSM namespace hold exactly want's keys. CSM
// owns these namespaces, so any other key, a duplicate, or a glob flag that
// disagrees with the key text is deleted.
func syncStalwartKeys(ctx context.Context, api stalwartAPI, want map[string][]string) (changed bool, err error) {
	added, removed := 0, 0
	for _, ns := range ipmap.StalwartNamespaces() {
		var have []stalwartapi.LookupKey
		if have, err = api.LookupKeys(ctx, ns); err != nil {
			break
		}
		wanted := make(map[string]bool, len(want[ns]))
		for _, k := range want[ns] {
			wanted[k] = true
		}
		var stale, missing []string
		for _, k := range have {
			if wanted[k.Key] && k.Glob == strings.Contains(k.Key, "*") {
				delete(wanted, k.Key)
			} else {
				stale = append(stale, k.ID)
			}
		}
		for _, k := range want[ns] {
			if wanted[k] {
				missing = append(missing, k)
				delete(wanted, k)
			}
		}
		// A failed write may have applied in part, so it counts as a change.
		if len(stale) > 0 {
			changed = true
			if err = api.DeleteLookupKeys(ctx, stale); err != nil {
				break
			}
			removed += len(stale)
		}
		if len(missing) > 0 {
			changed = true
			if err = api.CreateLookupKeys(ctx, ns, missing); err != nil {
				break
			}
			added += len(missing)
		}
	}
	if !changed {
		return false, err
	}
	csmlog.Info("stalwart address list updated", "added", added, "removed", removed)
	// Reload even after a failed write so the loaded list matches the stored keys.
	var reloadErr error
	for range 2 {
		reloadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		reloadErr = api.ReloadLookupStores(reloadCtx)
		cancel()
		if reloadErr == nil {
			return true, err
		}
	}
	return true, errors.Join(err, fmt.Errorf("reloading Stalwart's lookup lists: %w", reloadErr))
}

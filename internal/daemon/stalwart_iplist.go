package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

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

// stalwartListState retains confirmed filter state and unfinished reloads between ticks.
type stalwartListState struct {
	m                  *ipmap.Map
	filterOff, ruleOff bool
	reloadPending      bool
}

// startStalwartAddressList syncs at start and every 10 minutes.
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

// stalwartListTick syncs the address list and settles its findings.
func (d *Daemon) stalwartListTick(ctx context.Context, now time.Time) []alert.Finding {
	cfg := d.currentCfg()
	m := ipmap.Build(ipmapSources(now, d.antispamInfraIPs(cfg)))
	st := stalwartListState{m: &m}
	if s := d.stalwart; s != nil {
		if previous := s.list.Load(); previous != nil {
			st.filterOff, st.ruleOff, st.reloadPending = previous.filterOff, previous.ruleOff, previous.reloadPending
		}
	}
	// Store the map before reading Stalwart so a hung read leaves evidence guarded.
	d.storeStalwartList(st)
	api, findings, filterKnown := stalwartListRead(ctx, cfg, &st, now)
	if filterKnown && st.filterOff {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning, Check: stalwartCheckFilterOff, DedupKey: "filter_off",
			Message:   "Stalwart's spam filter is off",
			Details:   "Stalwart does not score incoming mail, so CSM's address list adds no score. Switch the spam filter on in Stalwart.",
			Timestamp: now,
		})
	}
	d.storeStalwartList(st)
	// Observe mode reads but leaves Stalwart's lookup lists as they are.
	if api != nil && !cfg.ObserveMode() {
		want := m.StalwartKeys()
		if st.ruleOff {
			want = nil
		}
		var err error
		st.reloadPending, err = syncStalwartKeys(ctx, api, want, st.reloadPending)
		if err != nil {
			findings = append(findings, stalwartListFinding(err, now))
		}
		d.storeStalwartList(st)
	}
	// A timed-out tick still reports; only shutdown leaves findings as they are.
	if !errors.Is(ctx.Err(), context.Canceled) {
		var owned []string
		// Observe mode cannot confirm recovery from a failed reload.
		if api == nil || !cfg.ObserveMode() || !st.reloadPending {
			owned = append(owned, stalwartCheckAddressList)
		}
		if filterKnown {
			owned = append(owned, stalwartCheckFilterOff)
		}
		d.store.RearmAbsentDedupFindings(owned, findings)
		d.processScanFindings(cfg, findings, owned, "stalwart")
	}
	return findings
}

func (d *Daemon) storeStalwartList(st stalwartListState) {
	if s := d.stalwart; s != nil {
		s.list.Store(&st)
	}
}

// stalwartListRead returns the client only after reading the rule permits a sync.
func stalwartListRead(ctx context.Context, cfg *config.Config, st *stalwartListState, now time.Time) (stalwartAPI, []alert.Finding, bool) {
	// Without a key, setup and doctor report what is missing.
	if _, err := os.Lstat(cfg.Stalwart.APIKeyFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			st.filterOff, st.ruleOff = false, false
			return nil, nil, true
		}
		return nil, []alert.Finding{stalwartListFinding(err, now)}, false
	}
	api, err := stalwartClient(cfg)
	if err != nil {
		return nil, []alert.Finding{stalwartListFinding(err, now)}, false
	}
	off, known := stalwartFilterOff(ctx, api)
	if known {
		st.filterOff = off
	}
	readCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
	rule, found, err := api.SpamRule(readCtx, stalwartsetup.AddressListRule)
	cancel()
	if err != nil {
		return nil, []alert.Finding{stalwartListFinding(err, now)}, known
	}
	st.ruleOff = !found || rule.Type != "Any" || !rule.Enabled
	return api, nil, known
}

// Either switch proves the filter off; both must be readable to prove it on.
func stalwartFilterOff(ctx context.Context, api stalwartAPI) (off, known bool) {
	readCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
	s, settingsErr := api.SpamSettings(readCtx)
	cancel()
	if settingsErr == nil && !s.Enabled {
		return true, true
	}
	readCtx, cancel = context.WithTimeout(ctx, stalwartCallTimeout)
	off, stageErr := api.SpamFilterStageOff(readCtx)
	cancel()
	if stageErr == nil && off {
		return true, true
	}
	return false, settingsErr == nil && stageErr == nil
}

func stalwartListFinding(err error, now time.Time) alert.Finding {
	msg := "CSM cannot keep its address list in Stalwart up to date"
	if errors.Is(err, stalwartapi.ErrForbidden) || stalwartMethodForbidden(err) {
		msg = "Stalwart refused CSM's key access to the address list; run csm stalwart setup"
	}
	// Bound server text before persisting it or sending it to alert sinks.
	details := strings.ToValidUTF8(truncateStr(err.Error(), 1024), "")
	details = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, details)
	return alert.Finding{
		Severity: alert.Warning, Check: stalwartCheckAddressList, DedupKey: "address_list",
		Message: msg, Details: details, Timestamp: now,
	}
}

// syncStalwartKeys owns each namespace and returns whether a reload still needs retrying.
func syncStalwartKeys(ctx context.Context, api stalwartAPI, want map[string][]string, reloadPending bool) (pending bool, err error) {
	changed := false
	added, removed := 0, 0
	for _, ns := range ipmap.StalwartNamespaces() {
		var have []stalwartapi.LookupKey
		callCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
		have, err = api.LookupKeys(callCtx, ns)
		cancel()
		if err != nil {
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
			callCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
			err = api.DeleteLookupKeys(callCtx, stale)
			cancel()
			if err != nil {
				break
			}
			removed += len(stale)
		}
		if len(missing) > 0 {
			changed = true
			callCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
			err = api.CreateLookupKeys(callCtx, ns, missing)
			cancel()
			if err != nil {
				break
			}
			added += len(missing)
		}
	}
	if !changed && !reloadPending {
		return false, err
	}
	if added+removed > 0 {
		csmlog.Info("stalwart address list updated", "added", added, "removed", removed)
	}
	// Reload even after a failed write so the loaded list matches the stored keys.
	var reloadErr error
	for range 2 {
		reloadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		reloadErr = api.ReloadLookupStores(reloadCtx)
		cancel()
		if reloadErr == nil {
			return false, err
		}
	}
	return true, errors.Join(err, fmt.Errorf("reloading Stalwart's lookup lists: %w", reloadErr))
}

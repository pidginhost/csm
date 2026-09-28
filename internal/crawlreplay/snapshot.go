package crawlreplay

import (
	"cmp"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strings"
)

// SnapshotVersion is the session snapshot format.
const SnapshotVersion = 1

// Invalidation reports which restored state a new configuration could not
// interpret. Invalid windows restart, so a complete new window is needed
// before any key is judged; invalid baselines restart cold; a changed
// identity contract drops every key. Active findings are never dropped:
// they stay active, uncertain, until a complete window judges them.
type Invalidation struct {
	Windows   bool `json:"windows"`
	Baselines bool `json:"baselines"`
	Identity  bool `json:"identity"`
}

type sessionSnapshot struct {
	FormatVersion   int            `json:"format_version"`
	Params          Params         `json:"params"`
	Sketch          *SketchParams  `json:"sketch,omitempty"`
	HashVersion     string         `json:"hash_version,omitempty"`
	Shuffle         uint64         `json:"shuffle"`
	IdentityVersion int            `json:"identity_version"`
	Sites           []siteSnapshot `json:"sites"`
}

type siteSnapshot struct {
	Site        string        `json:"site"`
	ProcessedTo int64         `json:"processed_to"`
	CoveredFrom int64         `json:"covered_from"`
	WindowFrom  int64         `json:"window_from"`
	Covered     []Span        `json:"covered"`
	States      []StateSpan   `json:"states"`
	Keys        []keySnapshot `json:"keys"`
	Retired     []KeyID       `json:"retired"`
}

type keySnapshot struct {
	Key       KeyID            `json:"key"`
	First     int64            `json:"first"`
	Learned   int64            `json:"learned"`
	LearnedTo int64            `json:"learned_to"`
	From      int64            `json:"from"`
	Slots     []slotSnapshot   `json:"slots"`
	Minutes   []minuteSnapshot `json:"minutes"`
	Sketches  []sketchSnapshot `json:"sketches"`
	Finding   *findingSnapshot `json:"finding,omitempty"`
}

type slotSnapshot struct {
	Slot int     `json:"slot"`
	Mean float64 `json:"mean"`
	Obs  int     `json:"obs"`
	Last int64   `json:"last"`
}

type countSnapshot struct {
	Name string `json:"name"`
	N    int64  `json:"n"`
}

type minuteSnapshot struct {
	Minute    int64           `json:"minute"`
	Total     int64           `json:"total"`
	Expensive int64           `json:"expensive"`
	Bindings  []countSnapshot `json:"bindings"`
	Labels    []countSnapshot `json:"labels"`
}

type sketchSnapshot struct {
	Minute  int64       `json:"minute"`
	Summary sketchState `json:"summary"`
}

type findingSnapshot struct {
	Since     int64          `json:"since"`
	Uncertain bool           `json:"uncertain"`
	PinFirst  int64          `json:"pin_first"`
	PinAt     int64          `json:"pin_at"`
	PinSlots  []slotSnapshot `json:"pin_slots"`
}

// Snapshot serializes the session between segments: configuration, every
// site's coverage and state history, and every key's baseline, window,
// summaries and finding. A session using a test hash override cannot be
// serialized.
func (s *ReplaySession) Snapshot() ([]byte, error) {
	if s.broken || (s.cfg.Sketch != nil && s.cfg.Sketch.Hash != nil) {
		return nil, ErrSession
	}
	snap := sessionSnapshot{FormatVersion: SnapshotVersion, Params: s.cfg.Params, Sketch: s.cfg.Sketch,
		Shuffle: s.cfg.Shuffle, IdentityVersion: s.cfg.IdentityVersion, Sites: []siteSnapshot{}}
	if s.cfg.Sketch != nil {
		snap.HashVersion = bindingHashPurpose
	}
	for _, name := range slices.Sorted(maps.Keys(s.sites)) {
		site := s.sites[name]
		ss := siteSnapshot{Site: name, ProcessedTo: site.processedTo, CoveredFrom: site.coveredFrom, WindowFrom: site.windowFrom,
			Covered: slices.Clone(site.covered), States: slices.Clone(site.siteStates), Keys: []keySnapshot{}, Retired: []KeyID{}}
		if ss.Covered == nil {
			ss.Covered = []Span{}
		}
		for _, id := range slices.SortedFunc(maps.Keys(site.keyStates), keyOrder) {
			ss.States = append(ss.States, site.keyStates[id]...)
		}
		if ss.States == nil {
			ss.States = []StateSpan{}
		}
		for _, id := range slices.SortedFunc(maps.Keys(site.keys), keyOrder) {
			ss.Keys = append(ss.Keys, snapshotKey(id, site.keys[id]))
		}
		ss.Retired = append(ss.Retired, slices.SortedFunc(maps.Keys(site.retired), keyOrder)...)
		snap.Sites = append(snap.Sites, ss)
	}
	return json.Marshal(snap)
}

func snapshotSlots(slots *[168]slot) []slotSnapshot {
	out := []slotSnapshot{}
	for i, sl := range slots {
		if sl.obs > 0 {
			out = append(out, slotSnapshot{Slot: i, Mean: sl.mean, Obs: sl.obs, Last: sl.last})
		}
	}
	return out
}

func snapshotCounts(counts map[string]int64) []countSnapshot {
	out := []countSnapshot{}
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, countSnapshot{Name: name, N: counts[name]})
	}
	return out
}

func snapshotKey(id KeyID, ks *keyState) keySnapshot {
	k := keySnapshot{Key: id, First: ks.baseline.first, Learned: ks.baseline.learned, LearnedTo: ks.learnedTo, From: ks.from,
		Slots: snapshotSlots(&ks.baseline.slots), Minutes: []minuteSnapshot{}, Sketches: []sketchSnapshot{}}
	for _, m := range slices.Sorted(maps.Keys(ks.minutes)) {
		mc := ks.minutes[m]
		k.Minutes = append(k.Minutes, minuteSnapshot{Minute: m, Total: mc.total, Expensive: mc.expensive,
			Bindings: snapshotCounts(mc.bindings), Labels: snapshotCounts(mc.labels)})
	}
	for _, m := range slices.Sorted(maps.Keys(ks.sketches)) {
		k.Sketches = append(k.Sketches, sketchSnapshot{Minute: m, Summary: ks.sketches[m].state()})
	}
	if f := ks.finding; f != nil {
		k.Finding = &findingSnapshot{Since: f.since, Uncertain: f.uncertain, PinFirst: f.pin.first, PinAt: f.pin.at, PinSlots: snapshotSlots(&f.pin.slots)}
	}
	return k
}

// Restore rebuilds a session from Snapshot bytes under cfg. State cfg
// cannot interpret is invalidated as Invalidation reports; threshold
// changes (R, F, K, D, C) invalidate nothing and never rewrite a pinned
// profile. Malformed or inconsistent snapshots are refused with ErrSession.
func Restore(raw []byte, cfg SessionConfig) (*ReplaySession, Invalidation, error) {
	if err := cfg.validate(); err != nil {
		return nil, Invalidation{}, err
	}
	var snap sessionSnapshot
	if err := DecodeStrictJSON(raw, &snap); err != nil {
		return nil, Invalidation{}, ErrSession
	}
	stored := SessionConfig{Params: snap.Params, Sketch: snap.Sketch, Shuffle: snap.Shuffle, IdentityVersion: snap.IdentityVersion}
	if snap.FormatVersion != SnapshotVersion || stored.validate() != nil || (snap.Sketch == nil) != (snap.HashVersion == "") || snap.Sites == nil {
		return nil, Invalidation{}, ErrSession
	}
	s := &ReplaySession{cfg: cfg, sites: map[string]*siteSession{}}
	for _, ss := range snap.Sites {
		if s.sites[ss.Site] != nil || !ValidSite(ss.Site) {
			return nil, Invalidation{}, ErrSession
		}
		site, err := restoreSite(ss, stored, snap.HashVersion == bindingHashPurpose)
		if err != nil {
			return nil, Invalidation{}, err
		}
		s.sites[ss.Site] = site
	}
	var inv Invalidation
	inv.Identity = stored.IdentityVersion != cfg.IdentityVersion
	inv.Baselines = inv.Identity || stored.Params.Baseline != cfg.Params.Baseline
	inv.Windows = inv.Baselines || stored.Params.W != cfg.Params.W || !sameSketch(snap.Sketch, snap.HashVersion, cfg.Sketch)
	for _, site := range s.sites {
		if inv.Identity {
			for id, ks := range site.keys {
				if ks.finding == nil {
					delete(site.keys, id)
					delete(site.active, id)
				}
			}
			clear(site.retired)
			clear(site.keyStates)
		}
		if inv.Windows {
			site.windowFrom = site.processedTo + 1
			site.restart()
		}
		if inv.Baselines {
			for _, ks := range site.keys {
				ks.baseline = NewBaseline(cfg.Params.Baseline, site.processedTo+1)
				ks.baseline.learned = site.processedTo
				ks.learnedTo = site.processedTo
				if ks.finding != nil {
					ks.finding.pin = ks.baseline.Pin(site.processedTo + 1)
					ks.finding.uncertain = true
				}
			}
		}
	}
	return s, inv, nil
}

func sameSketch(stored *SketchParams, hashVersion string, current *SketchParams) bool {
	if stored == nil || current == nil {
		return stored == nil && current == nil
	}
	return current.Hash == nil && hashVersion == bindingHashPurpose &&
		stored.M == current.M && stored.H == current.H && stored.Seed == current.Seed
}

func restoreSite(ss siteSnapshot, cfg SessionConfig, checkHash bool) (*siteSession, error) {
	site := newSiteSession()
	site.processedTo, site.coveredFrom, site.windowFrom = ss.ProcessedTo, ss.CoveredFrom, ss.WindowFrom
	switch {
	case ss.ProcessedTo > 0 && len(ss.Covered) == 0:
		return nil, ErrSession
	case ss.ProcessedTo < 0, ss.Covered == nil, ss.States == nil, ss.Keys == nil, ss.Retired == nil:
		return nil, ErrSession
	case ss.ProcessedTo == 0 && (len(ss.Covered) > 0 || ss.CoveredFrom != 0 || ss.WindowFrom != 0 || len(ss.Keys) > 0 || len(ss.Retired) > 0):
		return nil, ErrSession
	}
	for i, sp := range ss.Covered {
		if sp.From <= 0 || sp.To < sp.From || (i > 0 && sp.From <= ss.Covered[i-1].To+1) {
			return nil, ErrSession
		}
	}
	if n := len(ss.Covered); n > 0 {
		last := ss.Covered[n-1]
		if last.To != ss.ProcessedTo || ss.CoveredFrom < last.From || ss.CoveredFrom > ss.ProcessedTo ||
			ss.WindowFrom < ss.CoveredFrom || ss.WindowFrom > ss.ProcessedTo+1 {
			return nil, ErrSession
		}
	}
	site.covered = ss.Covered
	byScope := map[KeyID][]StateSpan{}
	for _, st := range ss.States {
		scope := KeyID{}
		if st.Key != nil {
			if !validKeyID(*st.Key) {
				return nil, ErrSession
			}
			scope = *st.Key
		}
		if !learningStates[st.State] || st.From <= 0 || st.To < st.From {
			return nil, ErrSession
		}
		for _, other := range byScope[scope] {
			if st.From <= other.To && other.From <= st.To {
				return nil, ErrSession
			}
		}
		byScope[scope] = append(byScope[scope], st)
		if st.Key == nil {
			site.siteStates = append(site.siteStates, st)
		} else {
			site.keyStates[*st.Key] = append(site.keyStates[*st.Key], st)
		}
	}
	for _, spans := range append([][]StateSpan{site.siteStates}, slices.Collect(maps.Values(site.keyStates))...) {
		slices.SortFunc(spans, func(a, b StateSpan) int { return cmp.Compare(a.From, b.From) })
	}
	for _, ks := range ss.Keys {
		if !validKeyID(ks.Key) || site.keys[ks.Key] != nil {
			return nil, ErrSession
		}
		state, err := restoreKey(ks, ss, cfg, checkHash)
		if err != nil {
			return nil, err
		}
		site.keys[ks.Key] = state
		if state.active {
			site.active[ks.Key] = state
		}
	}
	for _, id := range ss.Retired {
		if !validKeyID(id) || id.Level == 3 || site.keys[id] != nil || site.retired[id] {
			return nil, ErrSession
		}
		site.retired[id] = true
	}
	return site, nil
}

func restoreSlots(in []slotSnapshot, first, learned int64) ([168]slot, error) {
	var out [168]slot
	seen := map[int]bool{}
	for _, sl := range in {
		if sl.Slot < 0 || sl.Slot >= 168 || seen[sl.Slot] || sl.Obs < 1 || math.IsNaN(sl.Mean) || math.IsInf(sl.Mean, 0) || sl.Mean < 0 ||
			sl.Last < first || sl.Last > learned || hourOfWeek(sl.Last) != sl.Slot {
			return out, ErrSession
		}
		seen[sl.Slot] = true
		out[sl.Slot] = slot{mean: sl.Mean, obs: sl.Obs, last: sl.Last}
	}
	return out, nil
}

// validLabelKey reports a window label counter name (see labelKey).
func validLabelKey(name string) bool {
	label, episode, episodic := strings.Cut(name, "/")
	if !episodic {
		return label == "" || label == LabelHealthy
	}
	return (label == LabelAttack || label == LabelOverload) && episodeID.MatchString(episode)
}

func restoreCounts(in []countSnapshot, valid func(string) bool) (map[string]int64, int64, error) {
	out := map[string]int64{}
	var sum int64
	for _, c := range in {
		if !valid(c.Name) || c.N < 1 || out[c.Name] != 0 {
			return nil, 0, ErrSession
		}
		out[c.Name] = c.N
		var ok bool
		if sum, ok = checkedSum(sum, c.N); !ok {
			return nil, 0, ErrSession
		}
	}
	return out, sum, nil
}

func restoreKey(k keySnapshot, ss siteSnapshot, cfg SessionConfig, checkHash bool) (*keyState, error) {
	w := int64(cfg.Params.W)
	switch {
	case k.First <= 0, k.Learned < 0, k.Learned > k.LearnedTo, k.LearnedTo > ss.ProcessedTo, k.LearnedTo < k.First-1,
		k.From < 0, k.From > ss.ProcessedTo, k.Slots == nil, k.Minutes == nil, k.Sketches == nil:
		return nil, ErrSession
	}
	slots, err := restoreSlots(k.Slots, k.First, k.Learned)
	if err != nil {
		return nil, err
	}
	ks := &keyState{baseline: &Baseline{p: cfg.Params.Baseline, first: k.First, learned: k.Learned, slots: slots},
		window: newWindow(), learnedTo: k.LearnedTo, from: k.From}
	minutes := map[int64]*minuteCounts{}
	for _, m := range k.Minutes {
		if m.Minute <= ss.ProcessedTo-w || m.Minute > ss.ProcessedTo || m.Minute < ss.WindowFrom || minutes[m.Minute] != nil ||
			m.Total < 1 || m.Expensive < 0 || m.Expensive > m.Total || (k.Key.Level < 3 && m.Expensive != m.Total) {
			return nil, ErrSession
		}
		bindings, bound, err := restoreCounts(m.Bindings, bindingPseudonym.MatchString)
		if err != nil || bound > m.Total {
			return nil, ErrSession
		}
		labels, labelled, err := restoreCounts(m.Labels, validLabelKey)
		if err != nil || labelled != m.Total {
			return nil, ErrSession
		}
		if _, ok := checkedSum(ks.window.Total(), m.Total); !ok {
			return nil, ErrSession
		}
		mc := &minuteCounts{bindings: bindings, total: m.Total, expensive: m.Expensive, labels: labels}
		minutes[m.Minute] = mc
		ks.window.apply(mc, 1)
	}
	sketches := map[int64]*keySketch{}
	for _, sk := range k.Sketches {
		mc := minutes[sk.Minute]
		if cfg.Sketch == nil || mc == nil || sketches[sk.Minute] != nil {
			return nil, ErrSession
		}
		restored, err := restoreSketch(*cfg.Sketch, sk.Summary)
		if err != nil {
			return nil, err
		}
		var bound int64
		for _, n := range mc.bindings {
			bound += n
		}
		for _, e := range restored.ss.entries {
			if n := mc.bindings[e.binding]; n == 0 || n > e.count || n < e.count-e.err {
				return nil, ErrSession
			}
		}
		witness := &bottomH{h: cfg.Sketch.H}
		for binding, n := range mc.bindings {
			if _, retained := restored.ss.index[binding]; !retained && n > restored.ss.floor() {
				return nil, ErrSession
			}
			if checkHash {
				witness.add(cfg.Sketch.hash(binding))
			}
		}
		// An older hash contract cannot be recomputed here; its windows
		// are discarded by Restore before any decision is allowed.
		if checkHash && !slices.Equal(witness.hashes, restored.hs.hashes) {
			return nil, ErrSession
		}
		if restored.bound != bound {
			return nil, ErrSession
		}
		sketches[sk.Minute] = restored
	}
	if cfg.Sketch != nil {
		for m, mc := range minutes {
			if len(mc.bindings) > 0 && sketches[m] == nil {
				return nil, ErrSession
			}
		}
	}
	if f := k.Finding; f != nil {
		if f.Since <= 0 || f.Since > ss.ProcessedTo || f.PinFirst != k.First ||
			f.PinAt < max(f.Since, f.PinFirst) || f.PinAt > ss.ProcessedTo+1 {
			return nil, ErrSession
		}
		pinSlots, err := restoreSlots(f.PinSlots, k.First, min(f.PinAt, ss.ProcessedTo))
		if err != nil {
			return nil, err
		}
		ks.finding = &finding{since: f.Since, uncertain: f.Uncertain,
			pin: Profile{p: cfg.Params.Baseline, first: f.PinFirst, at: f.PinAt, slots: pinSlots}}
	}
	ks.active = ks.finding != nil || ks.window.Total() > 0
	if ks.active {
		ks.minutes, ks.sketches = minutes, sketches
	} else if len(minutes) > 0 {
		return nil, ErrSession
	}
	return ks, nil
}

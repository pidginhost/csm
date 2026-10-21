package mailstats

import (
	"cmp"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"
)

// Store keeps the counter across restarts. *store.DB implements it.
type Store interface {
	PutMailStats(buckets map[int64][]byte, rejects map[string][]byte, pruneBefore int64) error
	MailStats() (map[int64][]byte, map[string][]byte, error)
	AddMailStatsGap(start, end int64) error
	MailStatsGaps(since int64) ([][2]int64, error)
	GetMetaString(key string) string
	SetMetaString(key, val string) error
}

const (
	metaSince     = "mailstats:since"
	metaFlushedAt = "mailstats:flushed_at"
)

// Load adds the stored counts to what the counter holds, since lines may
// already have been counted, restores the reject rings and gaps, and
// records the stretch from the last flush to the counter's start as a gap.
// Every stop is one: a clean shutdown flushes as it stops, and after a crash
// the lines since the last flush were lost. Ending it at the start rather
// than at now keeps a retried Load from counting time already counted. A
// corrupt entry, an unknown class or an entry out of range is skipped. A
// failed load leaves live counts unchanged and can be retried. Once a Load
// succeeds, later calls do nothing.
func (c *Counter) Load(db Store, now time.Time) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	if c.loaded {
		return nil
	}

	stored, rings, err := db.MailStats()
	if err != nil {
		return err
	}
	pairs, err := db.MailStatsGaps(now.Add(-Retention).Unix())
	if err != nil {
		return err
	}
	gaps := make([]Span, 0, len(pairs)+1)
	for _, p := range pairs {
		gaps = append(gaps, Span{time.Unix(p[0], 0).UTC(), time.Unix(p[1], 0).UTC()})
	}
	end := c.start.UTC()
	flushed, ferr := time.Parse(time.RFC3339, db.GetMetaString(metaFlushedAt))
	newGap := ferr == nil && end.After(flushed)
	if newGap {
		// Gap storage has second precision. Round outward so a positive
		// stop within one second survives both this load and later restarts.
		flushed = flushed.UTC().Truncate(time.Second)
		if rounded := end.Truncate(time.Second); rounded.Before(end) {
			end = rounded.Add(time.Second)
		}
		gaps = append(gaps, Span{flushed, end})
	}
	since, serr := time.Parse(time.RFC3339, db.GetMetaString(metaSince))
	buckets := decodeBuckets(stored, now)
	restored := decodeRings(rings, now)

	c.mu.Lock()
	if serr != nil {
		since = c.since.UTC().Truncate(time.Second)
	}
	c.mu.Unlock()
	// Commit startup metadata before merging. On failure Flush must remain
	// memory-only, and a retry must not add the stored counts twice.
	var errs []error
	if newGap {
		errs = append(errs, db.AddMailStatsGap(flushed.Unix(), end.Unix()))
	}
	if serr != nil {
		errs = append(errs, db.SetMetaString(metaSince, since.Format(time.RFC3339)))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	c.mu.Lock()
	c.since = since
	for k, b := range buckets {
		if live := c.bucket(k); live != nil {
			live.add(b)
		}
	}
	c.mergeRings(restored)
	// Re-numbering changes ties across classes. Persist every restored ring,
	// including ones whose entries all expired, so disk matches memory.
	for class := range rings {
		if slices.Contains(Classes, Class(class)) {
			c.ringDirty[Class(class)] = true
		}
	}
	c.gaps = append(c.gaps, gaps...)
	slices.SortFunc(c.gaps, func(x, y Span) int { return x.Start.Compare(y.Start) })
	c.mu.Unlock()
	c.loaded = true

	return nil
}

// Flush prunes the counter, writes the buckets and rings that changed since
// the last successful write, prunes the store past Retention and records
// the flush time. Before a Load has merged it only prunes memory, so the
// store is never overwritten with live counts alone. After a failed write
// the changes stay marked for the next Flush.
func (c *Counter) Flush(db Store, now time.Time) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.Prune(now)
	if !c.loaded {
		return nil
	}

	c.mu.Lock()
	buckets := make(map[int64][]byte, len(c.dirty))
	for k := range c.dirty {
		buckets[k], _ = json.Marshal(c.buckets[k])
	}
	rejects := make(map[string][]byte, len(c.ringDirty))
	for class := range c.ringDirty {
		ring := c.rings[class]
		if ring == nil {
			ring = []ringEntry{}
		}
		rejects[string(class)], _ = json.Marshal(ring)
	}
	dirty, ringDirty := c.dirty, c.ringDirty
	c.dirty, c.ringDirty = map[int64]bool{}, map[Class]bool{}
	c.mu.Unlock()

	if err := db.PutMailStats(buckets, rejects, now.Add(-Retention).Unix()); err != nil {
		c.mu.Lock()
		for k := range dirty {
			if c.buckets[k] != nil {
				c.dirty[k] = true
			}
		}
		maps.Copy(c.ringDirty, ringDirty)
		c.mu.Unlock()
		return err
	}
	return db.SetMetaString(metaFlushedAt, now.UTC().Format(time.RFC3339Nano))
}

// Prune drops buckets past Retention, ring entries past RingAge and gaps
// that ended before Retention. Flush calls it; without a store, call it on
// a timer to keep the counter bounded.
func (c *Counter) Prune(now time.Time) {
	cut, ringCut := now.Add(-Retention), now.Add(-RingAge)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.buckets {
		if k < cut.Unix() {
			delete(c.buckets, k)
			delete(c.dirty, k)
		}
	}
	for class, ring := range c.rings {
		if kept := slices.DeleteFunc(ring, func(e ringEntry) bool { return e.At.Before(ringCut) }); len(kept) < len(ring) {
			c.rings[class] = kept
			c.ringDirty[class] = true
		}
	}
	c.gaps = slices.DeleteFunc(c.gaps, func(g Span) bool { return g.End.Before(cut) })
}

// decodeBuckets returns the stored buckets that decode, start on a bucket
// boundary and fall in the range the counter keeps at now.
func decodeBuckets(stored map[int64][]byte, now time.Time) map[int64]*bucket {
	lo, hi := now.Add(-Retention).Unix(), now.Add(time.Hour).Unix()
	out := map[int64]*bucket{}
	for k, raw := range stored {
		var b bucket
		if k%BucketSeconds != 0 || k < lo || k > hi || json.Unmarshal(raw, &b) != nil {
			continue
		}
		out[k] = &b
	}
	return out
}

// decodeRings returns the stored ring entries of known classes, in the ring
// of their own class, that are newer than RingAge at now.
func decodeRings(rings map[string][]byte, now time.Time) []ringEntry {
	lo, hi := now.Add(-RingAge), now.Add(time.Hour)
	var out []ringEntry
	for key, raw := range rings {
		class := Class(key)
		var ring []ringEntry
		if !slices.Contains(Classes, class) || json.Unmarshal(raw, &ring) != nil {
			continue
		}
		for _, e := range ring {
			if e.Class == class && !e.At.Before(lo) && !e.At.After(hi) {
				out = append(out, e)
			}
		}
	}
	return out
}

// add adds o's counts to b.
func (b *bucket) add(o *bucket) {
	for k, n := range o.Scans {
		b.Scans[k] += n
	}
	for k, n := range o.Rejects {
		b.Rejects[k] += n
	}
	for k, n := range o.Temporary {
		b.Temporary[k] += n
	}
	b.LoginsSMTP += o.LoginsSMTP
	b.LoginsMailbox += o.LoginsMailbox
	b.Quarantined += o.Quarantined
	for k, n := range o.Sends {
		if b.Sends == nil {
			b.Sends = map[string]int{}
		}
		b.Sends[k] += n
	}
}

// mergeRings merges restored entries into the live rings. Restored entries
// arrived before live ones, so all are numbered again in that order; each
// class then keeps its newest RingSize by time. The caller holds c.mu.
func (c *Counter) mergeRings(restored []ringEntry) {
	live := slices.Concat(slices.Collect(maps.Values(c.rings))...)
	bySeq := func(x, y ringEntry) int { return cmp.Compare(x.Seq, y.Seq) }
	slices.SortFunc(restored, bySeq)
	slices.SortFunc(live, bySeq)
	c.seq = 0
	rings := map[Class][]ringEntry{}
	for _, e := range slices.Concat(restored, live) {
		c.seq++
		e.Seq = c.seq
		rings[e.Class] = append(rings[e.Class], e)
	}
	for class, ring := range rings {
		slices.SortFunc(ring, func(x, y ringEntry) int { return cmp.Or(x.At.Compare(y.At), cmp.Compare(x.Seq, y.Seq)) })
		rings[class] = ring[max(0, len(ring)-RingSize):]
	}
	c.rings = rings
}

// clipGaps clips gaps to [from, to), merges the ones that overlap and
// returns them with their length in minutes.
func clipGaps(gaps []Span, from, to time.Time) ([]Span, int) {
	out := []Span{}
	var total time.Duration
	for _, g := range gaps {
		if g.Start.Before(from) {
			g.Start = from
		}
		if g.End.After(to) {
			g.End = to
		}
		if !g.End.After(g.Start) {
			continue
		}
		if n := len(out); n > 0 && !g.Start.After(out[n-1].End) {
			if g.End.After(out[n-1].End) {
				total += g.End.Sub(out[n-1].End)
				out[n-1].End = g.End
			}
			continue
		}
		total += g.End.Sub(g.Start)
		out = append(out, g)
	}
	if total > 0 {
		// Even a short restart loses coverage; zero would hide it in the UI.
		return out, max(1, int(total.Round(time.Minute)/time.Minute))
	}
	return out, 0
}

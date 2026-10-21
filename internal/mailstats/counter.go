package mailstats

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

const (
	// BucketSeconds is the bucket width. Every real zone offset is a
	// multiple of 15 minutes, so the browser can build days in any zone.
	BucketSeconds = 900
	Retention     = 30 * 24 * time.Hour
	RingSize      = 200
	RingAge       = 7 * 24 * time.Hour

	scanJoinSize = 1024
	bucketLimit  = int(Retention / (BucketSeconds * time.Second))
)

// Span is a stretch of time.
type Span struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Totals sums a range. A dry-run tag or reject delivered the message
// unchanged, so it counts as clean and as would-tag or would-reject, never
// as tagged or rejected. A scan whose message was then rejected or
// quarantined as malware counts only as scanned. Rejects counts every
// reject per class; Temporary is the temporary subset.
type Totals struct {
	Scanned       int           `json:"scanned"`
	Clean         int           `json:"clean"`
	Tagged        int           `json:"tagged"`
	Rejected      int           `json:"rejected"`
	WouldTag      int           `json:"would_tag"`
	WouldReject   int           `json:"would_reject"`
	Unfiltered    int           `json:"unfiltered"`
	ScanErrors    int           `json:"scan_errors"`
	Rejects       map[Class]int `json:"rejects"`
	Temporary     map[Class]int `json:"temporary"`
	Quarantined   int           `json:"quarantined"`
	LoginsSMTP    int           `json:"logins_smtp"`
	LoginsMailbox int           `json:"logins_mailbox"`
}

// Point is one bucket of the chart. T is the bucket start in unix seconds.
// A temporary reject defers the message rather than deciding it, so no
// series counts one.
type Point struct {
	T        int64 `json:"t"`
	Clean    int   `json:"clean"`
	Tagged   int   `json:"tagged"`
	Rejected int   `json:"rejected"`
	Malware  int   `json:"malware"`
	Other    int   `json:"other"`
}

// Overview is what the counter knows about [From, To).
type Overview struct {
	From             time.Time `json:"from"`
	To               time.Time `json:"to"`
	CountingSince    time.Time `json:"counting_since,omitzero"`
	UncountedMinutes int       `json:"uncounted_minutes"`
	Gaps             []Span    `json:"gaps"`
	Totals           Totals    `json:"totals"`
	Series           []Point   `json:"series"`
}

// bucket holds the counts of one BucketSeconds window. Scans is keyed by
// mode + ":" + outcome, where outcome is the scan decision, "error", or
// "malware" once a malware reject or quarantine of the message followed.
// Temporary is the subset of Rejects that were temporary.
type bucket struct {
	Scans         map[string]int
	Rejects       map[Class]int
	Temporary     map[Class]int
	LoginsSMTP    int
	LoginsMailbox int
	Quarantined   int
}

// scanRef is what the join keeps of a message: the score of its successful
// scan and the bucket and Scans key that scan counted under. Key is empty
// while no scan has been seen. Malware is set once a malware reject or
// quarantine of the message took its scan out of clean, or will.
type scanRef struct {
	score   int
	bucket  int64
	key     string
	malware bool
}

// ringEntry is a reject in its class ring. Seq orders entries with the
// same time across rings by arrival.
type ringEntry struct {
	Reject
	Seq uint64 `json:"seq"`
}

// Counter counts mail decisions in memory by the time the log line gives.
type Counter struct {
	now func() time.Time
	// start is when New ran, or what SetStart set, and so the end of any
	// stop Load records. Unlike since, Load never replaces it. Guarded by
	// persistMu.
	start time.Time

	// persistMu serializes Load and Flush. A Flush that writes between
	// Load's read and its merge, or two Flushes that write out of order,
	// would store stale counts.
	persistMu sync.Mutex
	// loaded is set once Load has merged the stored counts. Until then a
	// write would replace stored counts with live ones. Guarded by
	// persistMu.
	loaded bool

	mu        sync.Mutex
	since     time.Time
	buckets   map[int64]*bucket
	dirty     map[int64]bool // buckets changed since the last stored write
	rings     map[Class][]ringEntry
	ringDirty map[Class]bool
	seq       uint64
	gaps      []Span // stretches CSM was stopped, by start
	scans     map[string]scanRef
	scanIDs   []string // FIFO of the keys of scans, oldest first
}

// New returns an empty counter that has counted since now().
func New(now func() time.Time) *Counter {
	start := now()
	return &Counter{
		now:       now,
		start:     start,
		since:     start,
		buckets:   map[int64]*bucket{},
		dirty:     map[int64]bool{},
		rings:     map[Class][]ringEntry{},
		ringDirty: map[Class]bool{},
		scans:     map[string]scanRef{},
	}
}

// SetStart sets when counting began, for a counter built before its log
// readers start, so the stop the first Load records ends there. It does
// nothing once a Load has succeeded.
func (c *Counter) SetStart(t time.Time) {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	if !c.loaded {
		c.start = t
		c.mu.Lock()
		c.since = t
		c.mu.Unlock()
	}
}

// RecordScan counts one scan marker. A failed scan counts as "error".
func (c *Counter) RecordScan(at time.Time, s antispam.Scan) {
	outcome := s.Decision
	if !s.OK {
		outcome = "error"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketAt(at)
	if b == nil {
		return
	}
	key := s.Mode + ":" + outcome
	if s.OK && s.MsgID != "" {
		ref := scanRef{score: s.Score, bucket: bucketStart(at), key: key}
		if prev := c.scans[s.MsgID]; prev.malware && prev.key == "" {
			// Quarantined before the log watcher read this marker.
			ref.key, ref.malware = s.Mode+":malware", true
		}
		c.rememberScan(s.MsgID, ref)
		key = ref.key
	}
	b.Scans[key]++
}

// RecordReject counts one reject and keeps it in its class ring when it is
// newer than RingAge. A spam reject whose message was scanned gets the scan
// score as its detail.
func (c *Counter) RecordReject(r Reject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketAt(r.At)
	if b == nil {
		return
	}
	b.Rejects[r.Class]++
	if r.Temporary {
		b.Temporary[r.Class]++
	} else if r.Class == ClassMalware {
		c.moveToMalware(r.MsgID)
	}
	if r.At.Before(c.now().Add(-RingAge)) {
		return
	}
	if ref, ok := c.scans[r.MsgID]; ok && r.Class == ClassSpam {
		r.Detail = fmt.Sprintf("score %.1f", float64(ref.score)/10)
	}
	c.seq++
	ring := c.rings[r.Class]
	// Equal timestamps keep arrival order, including across classes.
	entry := ringEntry{Reject: r, Seq: c.seq}
	i, _ := slices.BinarySearchFunc(ring, entry, func(x, y ringEntry) int {
		return cmp.Or(x.At.Compare(y.At), cmp.Compare(x.Seq, y.Seq))
	})
	ring = slices.Insert(ring, i, entry)
	c.rings[r.Class] = slices.Delete(ring, 0, max(0, len(ring)-RingSize))
	c.ringDirty[r.Class] = true
}

// RecordLoginFailure counts n failed logins, SMTP or mailbox.
func (c *Counter) RecordLoginFailure(at time.Time, mailbox bool, n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketAt(at)
	switch {
	case b == nil:
	case mailbox:
		b.LoginsMailbox += n
	default:
		b.LoginsSMTP += n
	}
}

// RecordQuarantine counts one message CSM quarantined. The spool watcher
// quarantines as soon as Exim accepts the message, often before the log
// watcher reads its scan marker; RecordScan then counts that scan as
// malware.
func (c *Counter) RecordQuarantine(at time.Time, msgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketAt(at)
	if b == nil {
		return
	}
	b.Quarantined++
	if _, ok := c.scans[msgID]; !ok && msgID != "" {
		c.rememberScan(msgID, scanRef{malware: true})
		return
	}
	c.moveToMalware(msgID)
}

// moveToMalware recounts the scan of msgID as a malware outcome. Exim logs
// the scan marker before the antivirus rejects the message, and the spool
// watcher quarantines only accepted mail, so the scan counted the message
// as clean, tagged or rejected. A scan moves once; one the join no longer
// holds, or whose bucket is gone, stays as it is. The caller holds c.mu.
func (c *Counter) moveToMalware(msgID string) {
	ref, ok := c.scans[msgID]
	if !ok || ref.malware {
		return
	}
	b := c.buckets[ref.bucket]
	if b == nil || b.Scans[ref.key] == 0 {
		return
	}
	mode, _, _ := strings.Cut(ref.key, ":")
	b.Scans[ref.key]--
	b.Scans[mode+":malware"]++
	c.dirty[ref.bucket] = true
	ref.malware = true
	c.scans[msgID] = ref
}

// bucketAt returns the bucket at falls in, creating it, or nil when at is
// more than Retention old or, like LineTime, more than an hour ahead. The
// caller holds c.mu.
func (c *Counter) bucketAt(at time.Time) *bucket {
	if now := c.now(); at.Before(now.Add(-Retention)) || at.Sub(now) > time.Hour {
		return nil
	}
	k := bucketStart(at)
	b := c.bucket(k)
	if b != nil {
		c.dirty[k] = true
	}
	return b
}

// bucketStart returns the start of the bucket at falls in, in unix seconds.
func bucketStart(at time.Time) int64 { return at.Unix() / BucketSeconds * BucketSeconds }

// bucket keeps the newest bucketLimit buckets even if persistence is stalled.
// A late record must not evict a newer bucket. The caller holds c.mu.
func (c *Counter) bucket(k int64) *bucket {
	b := c.buckets[k]
	if b == nil {
		if len(c.buckets) == bucketLimit {
			oldest := k
			for start := range c.buckets {
				oldest = min(oldest, start)
			}
			if oldest == k {
				return nil
			}
			delete(c.buckets, oldest)
			delete(c.dirty, oldest)
		}
		b = &bucket{Scans: map[string]int{}, Rejects: map[Class]int{}, Temporary: map[Class]int{}}
		c.buckets[k] = b
	}
	return b
}

// rememberScan keeps the last scanJoinSize messages seen in a successful
// scan or a quarantine, by message ID. The caller holds c.mu.
func (c *Counter) rememberScan(msgID string, ref scanRef) {
	if _, ok := c.scans[msgID]; !ok {
		if len(c.scanIDs) == scanJoinSize {
			delete(c.scans, c.scanIDs[0])
			c.scanIDs = c.scanIDs[1:]
		}
		c.scanIDs = append(c.scanIDs, msgID)
	}
	c.scans[msgID] = ref
}

// Overview sums the buckets that start in [from, to).
func (c *Counter) Overview(from, to time.Time) Overview {
	type keyed struct {
		t int64
		b bucket
	}
	var in []keyed
	c.mu.Lock()
	since, gaps := c.since, slices.Clone(c.gaps)
	for k, b := range c.buckets {
		if start := time.Unix(k, 0); !start.Before(from) && start.Before(to) {
			cp := *b
			cp.Scans, cp.Rejects, cp.Temporary = maps.Clone(b.Scans), maps.Clone(b.Rejects), maps.Clone(b.Temporary)
			in = append(in, keyed{k, cp})
		}
	}
	c.mu.Unlock()

	slices.SortFunc(in, func(x, y keyed) int { return cmp.Compare(x.t, y.t) })
	ov := Overview{From: from, To: to, CountingSince: since,
		Totals: Totals{Rejects: map[Class]int{}, Temporary: map[Class]int{}}, Series: make([]Point, 0, len(in))}
	ov.Gaps, ov.UncountedMinutes = clipGaps(gaps, from, to)
	tot := &ov.Totals
	for _, e := range in {
		p := Point{T: e.t}
		for key, n := range e.b.Scans {
			mode, outcome, _ := strings.Cut(key, ":")
			enforce := mode == "enforce"
			tot.Scanned += n
			switch {
			case outcome == "error":
				tot.ScanErrors += n
			case outcome == "malware":
				// Scanned only: the reject or quarantine counts it as malware.
			case outcome == "tag" && enforce:
				p.Tagged += n
			case outcome == "reject" && enforce:
				p.Rejected += n
			default:
				p.Clean += n
				switch outcome {
				case "unfiltered":
					tot.Unfiltered += n
				case "tag":
					tot.WouldTag += n
				case "reject":
					tot.WouldReject += n
				}
			}
		}
		for class, n := range e.b.Temporary {
			tot.Temporary[class] += n
		}
		for class, n := range e.b.Rejects {
			tot.Rejects[class] += n
			permanent := n - e.b.Temporary[class]
			switch class {
			case ClassSpam, ClassRateLimited:
			case ClassMalware:
				p.Malware += permanent
			default:
				p.Other += permanent
			}
		}
		p.Malware += e.b.Quarantined
		tot.Clean += p.Clean
		tot.Tagged += p.Tagged
		tot.Rejected += p.Rejected
		tot.Quarantined += e.b.Quarantined
		tot.LoginsSMTP += e.b.LoginsSMTP
		tot.LoginsMailbox += e.b.LoginsMailbox
		ov.Series = append(ov.Series, p)
	}
	return ov
}

// Rejects returns up to limit ring entries of the given classes, every
// class when classes is empty, with At in [from, to) and newer than
// RingAge. The newest come first; entries with the same time come newest
// arrival first.
func (c *Counter) Rejects(from, to time.Time, classes []Class, limit int) []Reject {
	if limit <= 0 {
		return []Reject{}
	}
	var got []ringEntry
	c.mu.Lock()
	cutoff := c.now().Add(-RingAge)
	for class, ring := range c.rings {
		if len(classes) > 0 && !slices.Contains(classes, class) {
			continue
		}
		for _, e := range ring {
			if !e.At.Before(from) && e.At.Before(to) && !e.At.Before(cutoff) {
				got = append(got, e)
			}
		}
	}
	c.mu.Unlock()

	slices.SortFunc(got, func(x, y ringEntry) int {
		return cmp.Or(y.At.Compare(x.At), cmp.Compare(y.Seq, x.Seq))
	})
	out := make([]Reject, 0, min(limit, len(got)))
	for _, e := range got[:min(limit, len(got))] {
		out = append(out, e.Reject)
	}
	return out
}

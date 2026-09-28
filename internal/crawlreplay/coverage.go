package crawlreplay

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// ProofVersion is the coverage proof format.
const ProofVersion = 1

// Reasons a proof gives for minutes of the recording period it does not
// certify, and the reason ValidateBundle gives for certified minutes that a
// bundle's own loss accounting removes.
const (
	ExcludedPartialMinute   = "partial_minute"
	ExcludedCollectionGap   = "collection_gap"
	ExcludedLivenessUnknown = "liveness_unknown"
	ExcludedTopologyChange  = "topology_change"
	ExcludedUnknownLoss     = "unknown_loss"
)

// Kinds of independent evidence a proof cites by digest.
const (
	EvidenceCollection     = "collection"
	EvidenceLiveness       = "logging_liveness"
	EvidenceLateness       = "lateness"
	EvidencePreApplication = "pre_application"
)

// ErrProof reports a coverage proof that breaks its format or does not
// describe the bundle it names.
var ErrProof = errors.New("crawlreplay: invalid coverage proof")

func proofError(field string) error { return fmt.Errorf("%w: %s", ErrProof, field) }

// CoverageProof is the operator's certificate of complete minutes, built
// from evidence independent of the logs: the collection record, logging and
// handler liveness, and the measured completion delay. The logs alone can
// never certify a minute, least of all a silent one.
type CoverageProof struct {
	FormatVersion  int    `json:"format_version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	// LatenessSeconds bounds how long after its logged time a request can
	// be written, which bounds where an untimed lost line belongs.
	LatenessSeconds int64           `json:"lateness_seconds"`
	Evidence        []ProofEvidence `json:"evidence"`
	Sites           []ProofSite     `json:"sites"`

	digest string
}

// ProofEvidence names one independent evidence file by digest; its content
// stays with the operator.
type ProofEvidence struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// ProofSite tiles the recording period for one site: certified spans and
// reasoned exclusions, disjoint, sorted and covering every minute.
type ProofSite struct {
	Site     string         `json:"site"`
	Spans    []Span         `json:"spans"`
	Excluded []Exclusion    `json:"excluded,omitempty"`
	Rejects  []RejectWaiver `json:"rejects,omitempty"`
}

// Exclusion is an inclusive range of minutes the proof cannot certify.
type Exclusion struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Reason string `json:"reason"`
}

// RejectWaiver states that exactly Lines lost lines of Category within an
// inclusive minute range were rejected before the application ran, as the
// cited pre-application evidence shows. The HTTP status alone is not that
// evidence. A waived line does not remove its minutes from coverage.
type RejectWaiver struct {
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Category string `json:"category"`
	Lines    int64  `json:"lines"`
	Evidence string `json:"evidence"`
}

// Digest returns the SHA-256 of the proof bytes DecodeCoverageProof read.
func (p *CoverageProof) Digest() string { return p.digest }

// DecodeCoverageProof decodes and checks a proof's closed format.
func DecodeCoverageProof(raw []byte) (*CoverageProof, error) {
	var p CoverageProof
	if err := DecodeStrictJSON(raw, &p); err != nil {
		return nil, proofError("syntax")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p.digest = hex.EncodeToString(sum[:])
	return &p, nil
}

var (
	exclusionReasons = map[string]bool{ExcludedPartialMinute: true, ExcludedCollectionGap: true, ExcludedLivenessUnknown: true, ExcludedTopologyChange: true}
	evidenceKinds    = map[string]bool{EvidenceCollection: true, EvidenceLiveness: true, EvidenceLateness: true, EvidencePreApplication: true}
	waivable         = map[string]bool{LossNoTarget: true, LossOversized: true}
)

// Validate checks the proof's own format; ValidateBundle checks it against
// a manifest.
func (p *CoverageProof) Validate() error {
	switch {
	case p.FormatVersion != ProofVersion:
		return proofError("format_version")
	case !sha256Hex.MatchString(p.ManifestSHA256):
		return proofError("manifest_sha256")
	case p.LatenessSeconds < 1 || p.LatenessSeconds > math.MaxInt32:
		return proofError("lateness_seconds")
	case len(p.Sites) == 0:
		return proofError("sites")
	}
	kinds := map[string]bool{}
	preApplication := map[string]bool{}
	seen := map[ProofEvidence]bool{}
	for _, e := range p.Evidence {
		if !evidenceKinds[e.Kind] || !sha256Hex.MatchString(e.SHA256) || seen[e] {
			return proofError("evidence")
		}
		seen[e], kinds[e.Kind] = true, true
		if e.Kind == EvidencePreApplication {
			preApplication[e.SHA256] = true
		}
	}
	if !kinds[EvidenceCollection] || !kinds[EvidenceLiveness] || !kinds[EvidenceLateness] {
		return proofError("evidence")
	}
	sites := map[string]bool{}
	for _, s := range p.Sites {
		if !ValidSite(s.Site) || sites[s.Site] || s.Spans == nil {
			return proofError("sites")
		}
		sites[s.Site] = true
		for i, span := range s.Spans {
			if span.From < 1 || span.To < span.From || (i > 0 && span.From <= s.Spans[i-1].To) {
				return proofError("spans")
			}
		}
		for _, e := range s.Excluded {
			if !exclusionReasons[e.Reason] || e.From < 1 || e.To < e.From {
				return proofError("excluded")
			}
		}
		for i, w := range s.Rejects {
			if !waivable[w.Category] || !preApplication[w.Evidence] || w.Lines < 1 || w.From < 1 || w.To < w.From {
				return proofError("rejects")
			}
			for _, other := range s.Rejects[:i] {
				if other.Category == w.Category && other.From <= w.To && w.From <= other.To {
					return proofError("rejects")
				}
			}
		}
	}
	return nil
}

// BundleInput is a decoded manifest, an optional proof and the two outputs.
type BundleInput struct {
	Manifest Manifest       // from DecodeManifest
	Proof    *CoverageProof // nil: coverage is unqualified
	Volume   io.Reader
	Records  io.Reader
}

// BundleVisitor receives a bundle's contents as ValidateBundle checks them:
// every volume row, then the validated sites, then every record in stream
// order. Anything built from them must be discarded if ValidateBundle
// returns an error, which it can do after the last callback.
type BundleVisitor struct {
	Volume func(Volume) error
	Sites  func([]BundleSite) error
	Record func(Record) error
}

// BundleSite is one validated site. Extent is the observed first and last
// placed minute. Certified is what the proof certifies and Coverage what a
// replay may use: certified minutes less any with unknown loss. Both are nil
// without a proof; an extent is never coverage.
type BundleSite struct {
	Site      string
	Account   string
	Extent    *Span
	Records   int64
	Certified []Span
	Coverage  []Span
	// Excluded counts period minutes outside Coverage by reason.
	Excluded map[string]int64
}

// ValidateBundle checks a bundle against its manifest and, when present,
// the coverage proof bound to that manifest, reading each output once. It
// returns every manifest site, including sites without records. Errors
// wrap ErrManifest, ErrProof, ErrBundle, ErrRecord or ErrDecode and name
// fields only.
func ValidateBundle(in BundleInput, identityVersion int, v BundleVisitor) ([]BundleSite, error) {
	c, err := newBundleCheck(in.Manifest, in.Proof, identityVersion)
	if err != nil {
		return nil, err
	}
	volume, err := ReadBundleFile(in.Volume, func(r io.Reader) error {
		return ReadVolume(r, func(row Volume) error {
			if rowErr := c.volume(row); rowErr != nil {
				return rowErr
			}
			if v.Volume != nil {
				return v.Volume(row)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sites, err := c.siteList()
	if err != nil {
		return nil, err
	}
	if v.Sites != nil {
		if err = v.Sites(sites); err != nil {
			return nil, err
		}
	}
	records, err := ReadBundleFile(in.Records, func(r io.Reader) error {
		return ReadRecords(r, func(rec Record) error {
			if rowErr := c.record(rec); rowErr != nil {
				return rowErr
			}
			if v.Record != nil {
				return v.Record(rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if err = c.finish(records, volume); err != nil {
		return nil, err
	}
	return sites, nil
}

type siteMinute struct {
	site   string
	minute int64
}

type siteState struct {
	m      *SiteManifest
	proof  *ProofSite
	inputs int
	done   bool
	seq    int64
	file   int
	// From records.
	records, unbound, infra int64
	labels                  map[string]int64
	lines, unboundLines     map[int64]int64
	// From volume rows.
	volumeLines, volumeUnbound, volumeNoTarget map[int64]int64
	volumeBytes                                int64
}

type bundleCheck struct {
	m        Manifest
	proof    *CoverageProof
	sites    map[string]*siteState
	volumes  map[siteMinute]bool
	l1Parent map[string]string
	l2Site   map[string]string
	current  *siteState
	vRows    int64
	rRows    int64
}

func bundleError(field string) error { return fmt.Errorf("%w: %s", ErrBundle, field) }

func newBundleCheck(m Manifest, proof *CoverageProof, identityVersion int) (*bundleCheck, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.IdentityVersion != identityVersion {
		return nil, manifestError("identity_version")
	}
	if m.digest == "" {
		return nil, manifestError("digest")
	}
	c := &bundleCheck{m: m, proof: proof, sites: map[string]*siteState{}, volumes: map[siteMinute]bool{},
		l1Parent: map[string]string{}, l2Site: map[string]string{}}
	for i := range m.Sites {
		c.sites[m.Sites[i].Site] = &siteState{m: &m.Sites[i], labels: map[string]int64{},
			lines: map[int64]int64{}, unboundLines: map[int64]int64{},
			volumeLines: map[int64]int64{}, volumeUnbound: map[int64]int64{}, volumeNoTarget: map[int64]int64{}}
	}
	for _, in := range m.Inputs {
		c.sites[in.Site].inputs++
	}
	if proof == nil {
		return c, nil
	}
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	if proof.ManifestSHA256 != m.digest {
		return nil, proofError("manifest_sha256")
	}
	if len(proof.Sites) != len(m.Sites) {
		return nil, proofError("sites")
	}
	for i := range proof.Sites {
		ps := &proof.Sites[i]
		s := c.sites[ps.Site]
		if s == nil || s.proof != nil {
			return nil, proofError("sites")
		}
		s.proof = ps
		if err := tiles(ps, m.Period); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// tiles checks that spans and exclusions cover the period exactly once.
func tiles(ps *ProofSite, period Span) error {
	parts := slices.Clone(ps.Spans)
	for _, e := range ps.Excluded {
		parts = append(parts, Span{From: e.From, To: e.To})
	}
	slices.SortFunc(parts, func(a, b Span) int { return cmp.Compare(a.From, b.From) })
	next := period.From
	for _, s := range parts {
		if s.From != next || s.To > period.To {
			return proofError("period")
		}
		next = s.To + 1
	}
	if next != period.To+1 {
		return proofError("period")
	}
	for _, w := range ps.Rejects {
		if !within(Span{From: w.From, To: w.To}, period) {
			return proofError("rejects")
		}
	}
	return nil
}

func (c *bundleCheck) placed(s *siteState, minute int64) bool {
	return s.m.Extent != nil && minute >= s.m.Extent.From && minute <= s.m.Extent.To
}

func (c *bundleCheck) volume(v Volume) error {
	s := c.sites[v.Site]
	key := siteMinute{v.Site, v.Minute}
	switch {
	case s == nil:
		return bundleError("volume site")
	case c.volumes[key]:
		return bundleError("duplicate volume row")
	case !c.placed(s, v.Minute):
		return bundleError("volume minute")
	}
	c.volumes[key] = true
	c.vRows++
	var ok bool
	if s.volumeBytes, ok = checkedSum(s.volumeBytes, v.Bytes); !ok {
		return bundleError("volume bytes")
	}
	s.volumeLines[v.Minute] = v.Lines
	s.volumeUnbound[v.Minute] = v.NoBinding
	s.volumeNoTarget[v.Minute] = v.NoTarget
	return nil
}

func (c *bundleCheck) record(r Record) error {
	s := c.sites[r.Site]
	if s == nil {
		return bundleError("record site")
	}
	if s != c.current {
		if c.current != nil {
			c.current.done = true
		}
		if s.done {
			return bundleError("site order")
		}
		c.current = s
	}
	minute := r.T / 60
	switch {
	case r.Account != s.m.Account:
		return bundleError("account")
	case r.Seq <= s.seq, r.Seq > s.m.Lines, r.File < s.file, r.File >= s.inputs:
		return bundleError("file order")
	case !c.placed(s, minute):
		return bundleError("record minute")
	}
	if r.L2 != "" {
		if site, ok := c.l2Site[r.L2]; ok && site != r.Site {
			return bundleError("l2 site")
		}
		c.l2Site[r.L2] = r.Site
		if parent, ok := c.l1Parent[r.L1]; ok && parent != r.L2 {
			return bundleError("l1 parent")
		}
		c.l1Parent[r.L1] = r.L2
	}
	s.seq, s.file = r.Seq, r.File
	c.rRows++
	s.records++
	s.lines[minute]++
	s.labels[r.Label]++
	if r.Binding == "" {
		s.unbound++
		s.unboundLines[minute]++
	}
	if r.Infra {
		s.infra++
	}
	return nil
}

// finish compares what was read with the manifest's outputs and totals.
func (c *bundleCheck) finish(records, volume Digest) error {
	for _, o := range c.m.Outputs {
		got, rows := records, c.rRows
		if o.Kind == "volume" {
			got, rows = volume, c.vRows
		}
		if got.SHA256 != o.SHA256 || got.Bytes != o.Bytes || rows != o.Rows {
			return bundleError("output " + o.Kind)
		}
	}
	for _, sm := range c.m.Sites {
		s := c.sites[sm.Site]
		volumeUnbound, noTarget := int64(0), int64(0)
		for m, n := range s.volumeUnbound {
			volumeUnbound += n
			noTarget += s.volumeNoTarget[m]
		}
		switch {
		case s.records != sm.Records, len(s.lines) != len(s.volumeLines):
			return bundleError("site records")
		case s.volumeBytes != sm.Bytes-sm.UnplacedBytes:
			return bundleError("site bytes")
		case s.unbound != sm.AttributionLoss+sm.InvalidClient, volumeUnbound != s.unbound:
			return bundleError("site bindings")
		case noTarget != sm.NoTarget:
			return bundleError("site targets")
		case s.infra != sm.Infrastructure:
			return bundleError("site infrastructure")
		}
		for m, n := range s.lines {
			if s.volumeLines[m] != n || s.volumeUnbound[m] != s.unboundLines[m] {
				return bundleError("site minutes")
			}
		}
		for label, n := range sm.Labels {
			if s.labels[label] != n {
				return bundleError("site labels")
			}
		}
	}
	return nil
}

// siteList returns every manifest site with its coverage, which requires every
// volume row: loss is counted per minute there.
func (c *bundleCheck) siteList() ([]BundleSite, error) {
	out := make([]BundleSite, 0, len(c.m.Sites))
	for _, sm := range c.m.Sites {
		s := c.sites[sm.Site]
		b := BundleSite{Site: sm.Site, Account: sm.Account, Extent: sm.Extent, Records: sm.Records}
		if s.proof != nil {
			var err error
			if b.Coverage, b.Excluded, err = c.coverage(s); err != nil {
				return nil, err
			}
			b.Certified = slices.Clone(s.proof.Spans)
		}
		out = append(out, b)
	}
	return out, nil
}

// coverage removes from the certified spans every minute a lost line may
// belong to, unless pre-application evidence waives exactly that loss.
func (c *bundleCheck) coverage(s *siteState) ([]Span, map[string]int64, error) {
	period, late := c.m.Period, c.proof.LatenessSeconds
	excluded := map[string]int64{}
	for _, e := range s.proof.Excluded {
		excluded[e.Reason] += e.To - e.From + 1
	}
	waived := map[int64]bool{}
	var cut []Span
	for _, w := range s.proof.Rejects {
		var lines int64
		switch w.Category {
		case LossNoTarget:
			for m, n := range s.volumeNoTarget {
				if n > 0 && m >= w.From && m <= w.To {
					lines += n
					waived[m] = true
				}
			}
		case LossOversized:
			for _, u := range s.m.Untimed {
				if b, ok := bracket(u, period, late); ok && u.Category == LossOversized && b.From >= w.From && b.To <= w.To {
					lines += u.Lines
				}
			}
		}
		if lines != w.Lines {
			return nil, nil, proofError("rejects")
		}
	}
	for m, n := range s.volumeNoTarget {
		if (n > 0 && !waived[m]) || s.volumeUnbound[m] > 0 {
			cut = append(cut, Span{From: m, To: m})
		}
	}
	for _, u := range s.m.Untimed {
		b, ok := bracket(u, period, late)
		if !ok {
			continue
		}
		covered := false
		for _, w := range s.proof.Rejects {
			covered = covered || (u.Category == LossOversized && w.Category == LossOversized && b.From >= w.From && b.To <= w.To)
		}
		if !covered {
			cut = append(cut, b)
		}
	}
	coverage := subtract(s.proof.Spans, cut)
	var certified, kept int64
	for _, sp := range s.proof.Spans {
		certified += sp.To - sp.From + 1
	}
	for _, sp := range coverage {
		kept += sp.To - sp.From + 1
	}
	if certified > kept {
		excluded[ExcludedUnknownLoss] = certified - kept
	}
	return coverage, excluded, nil
}

// bracket is the minute range an untimed lost line may belong to, within
// the period; ok is false when the range lies wholly outside it.
func bracket(u UntimedLoss, period Span, late int64) (Span, bool) {
	lo, hi := period.From, period.To
	after, before := u.After, u.Before
	if after > 0 && before > 0 && after > before {
		// Out-of-order neighbours: take the wider bound of the two.
		after, before = before, after
	}
	if after > 0 {
		lo = max(lo, floorMinute(after-late))
	}
	if before > 0 {
		upper, ok := checkedSum(before, late)
		if !ok {
			upper = math.MaxInt64
		}
		hi = min(hi, floorMinute(upper))
	}
	return Span{From: lo, To: hi}, lo <= hi
}

func floorMinute(sec int64) int64 {
	if sec < 0 {
		return (sec - 59) / 60
	}
	return sec / 60
}

// subtract removes every minute of cut from sorted disjoint spans.
func subtract(spans, cut []Span) []Span {
	slices.SortFunc(cut, func(a, b Span) int { return cmp.Compare(a.From, b.From) })
	var out []Span
	for _, s := range spans {
		from := s.From
		for _, c := range cut {
			if c.To < from || c.From > s.To {
				continue
			}
			if c.From > from {
				out = append(out, Span{From: from, To: c.From - 1})
			}
			from = max(from, c.To+1)
		}
		if from <= s.To {
			out = append(out, Span{From: from, To: s.To})
		}
	}
	return out
}

// RestrictToCoverage returns the records whose minute lies in coverage, in
// their original order, for a replay over validated coverage.
func RestrictToCoverage(records []Record, coverage []Span) []Record {
	var out []Record
	for _, r := range records {
		m := r.T / 60
		i, found := slices.BinarySearchFunc(coverage, m, func(s Span, m int64) int { return cmp.Compare(s.To, m) })
		if found || (i < len(coverage) && coverage[i].From <= m) {
			out = append(out, r)
		}
	}
	return out
}

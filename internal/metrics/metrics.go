// Package metrics is CSM's local OpenMetrics implementation. It exists
// so the daemon can expose a `/metrics` endpoint (ROADMAP item 4)
// without pulling in `github.com/prometheus/client_golang`, which
// would add ~20 transitive dependencies for the handful of counters,
// gauges, and histograms this project actually needs.
//
// The surface is intentionally narrow: Counter, Gauge, Histogram, and
// their labelled vector siblings. No summaries, no collectors, no
// custom exposition formats. Metric objects are safe for concurrent
// use; registration is idempotent.
package metrics

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// metricType discriminates the OpenMetrics TYPE line.
type metricType string

const (
	typeCounter   metricType = "counter"
	typeGauge     metricType = "gauge"
	typeHistogram metricType = "histogram"
)

// collectable is any metric that can write its exposition form to w.
// Kept unexported; registry drives it.
type collectable interface {
	writeTo(w *bufferedWriter)
}

// Registry holds a set of metrics and a lazily-refreshed snapshot of
// callback-driven gauges. Scraping takes a read lock; registration
// takes a write lock. Both are short-lived.
type Registry struct {
	mu           sync.RWMutex
	entries      []registered
	names        map[string]struct{}
	gaugeHooks   []gaugeHook
	counterHooks []counterHook
}

type registered struct {
	name string
	c    collectable
}

type gaugeHook struct {
	name string
	help string
	fn   func() float64
}

type counterHook struct {
	name string
	help string
	fn   func() float64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{names: map[string]struct{}{}}
}

// MustRegister panics if a metric of the same name is already
// registered. Daemons call this once at startup; a duplicate is a
// programming error.
func (r *Registry) MustRegister(name string, c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.names[name]; dup {
		panic(fmt.Sprintf("metrics: duplicate registration %q", name))
	}
	r.names[name] = struct{}{}
	r.entries = append(r.entries, registered{name: name, c: c})
}

// RegisterGaugeFunc exposes a value produced by calling fn at scrape
// time. Useful for "ask the OS for the bbolt file size" metrics where
// caching the value would be wrong.
func (r *Registry) RegisterGaugeFunc(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.names[name]; dup {
		panic(fmt.Sprintf("metrics: duplicate registration %q", name))
	}
	r.names[name] = struct{}{}
	r.gaugeHooks = append(r.gaugeHooks, gaugeHook{name: name, help: help, fn: fn})
}

// RegisterCounterFunc is the counter equivalent of RegisterGaugeFunc.
// Exposition must be monotonically non-decreasing across calls;
// callers are on the hook for that invariant.
func (r *Registry) RegisterCounterFunc(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.names[name]; dup {
		panic(fmt.Sprintf("metrics: duplicate registration %q", name))
	}
	r.names[name] = struct{}{}
	r.counterHooks = append(r.counterHooks, counterHook{name: name, help: help, fn: fn})
}

// WriteOpenMetrics renders a scrape in the OpenMetrics text format.
// The output ends with the `# EOF` marker that Prometheus requires
// when served as `Content-Type: application/openmetrics-text`.
func (r *Registry) WriteOpenMetrics(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bw := newBufferedWriter(w)

	// Stable ordering matters for diffs and for human reading. Sort
	// by name at scrape time; registration order is not stable across
	// restarts because goroutines may register concurrently.
	entries := make([]registered, len(r.entries))
	copy(entries, r.entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	for _, e := range entries {
		e.c.writeTo(bw)
	}

	gauges := append([]gaugeHook(nil), r.gaugeHooks...)
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })
	for _, h := range gauges {
		bw.writeMeta(h.name, h.help, typeGauge)
		bw.writeSample(h.name, nil, h.fn())
	}

	counters := append([]counterHook(nil), r.counterHooks...)
	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	for _, h := range counters {
		bw.writeMeta(h.name, h.help, typeCounter)
		bw.writeSample(h.name, nil, h.fn())
	}

	bw.writeEOF()
	return bw.err
}

// -----------------------------------------------------------------------
// Counter
// -----------------------------------------------------------------------

// Counter is a monotonically non-decreasing float value.
type Counter struct {
	name string
	help string
	// Stored as bits of a float64 so Add can safely work on values
	// that never need to fit into int64 (e.g., byte counts).
	bits uint64
}

// NewCounter constructs an unregistered Counter. Register with
// Registry.MustRegister(name, c).
func NewCounter(name, help string) *Counter {
	return &Counter{name: name, help: help}
}

// Add increments the counter by v. Panics on negative v; counters are
// monotonic by contract.
func (c *Counter) Add(v float64) {
	if v < 0 {
		panic(fmt.Sprintf("metrics: counter %q Add(%g): negative delta", c.name, v))
	}
	for {
		old := atomic.LoadUint64(&c.bits)
		newVal := math.Float64frombits(old) + v
		if atomic.CompareAndSwapUint64(&c.bits, old, math.Float64bits(newVal)) {
			return
		}
	}
}

// Inc adds 1.
func (c *Counter) Inc() { c.Add(1) }

// Value returns the current counter value. Useful in tests.
func (c *Counter) Value() float64 {
	return math.Float64frombits(atomic.LoadUint64(&c.bits))
}

func (c *Counter) writeTo(w *bufferedWriter) {
	w.writeMeta(c.name, c.help, typeCounter)
	w.writeSample(c.name, nil, c.Value())
}

// -----------------------------------------------------------------------
// Gauge
// -----------------------------------------------------------------------

// Gauge is a point-in-time numeric value that can go up or down.
type Gauge struct {
	name string
	help string
	bits uint64
}

// NewGauge constructs an unregistered Gauge.
func NewGauge(name, help string) *Gauge {
	return &Gauge{name: name, help: help}
}

// Set replaces the gauge value.
func (g *Gauge) Set(v float64) {
	atomic.StoreUint64(&g.bits, math.Float64bits(v))
}

// Add updates the gauge by v (may be negative).
func (g *Gauge) Add(v float64) {
	for {
		old := atomic.LoadUint64(&g.bits)
		newVal := math.Float64frombits(old) + v
		if atomic.CompareAndSwapUint64(&g.bits, old, math.Float64bits(newVal)) {
			return
		}
	}
}

// Inc adds 1. Dec subtracts 1.
func (g *Gauge) Inc() { g.Add(1) }
func (g *Gauge) Dec() { g.Add(-1) }

// Value returns the current gauge value.
func (g *Gauge) Value() float64 {
	return math.Float64frombits(atomic.LoadUint64(&g.bits))
}

func (g *Gauge) writeTo(w *bufferedWriter) {
	w.writeMeta(g.name, g.help, typeGauge)
	w.writeSample(g.name, nil, g.Value())
}

// -----------------------------------------------------------------------
// Histogram
// -----------------------------------------------------------------------

// Histogram is a cumulative histogram with fixed upper-bound buckets.
// Buckets must be strictly increasing; the implicit +Inf bucket is
// appended automatically.
type Histogram struct {
	name      string
	help      string
	upper     []float64
	bucketCnt []uint64 // atomic counters per bucket (last entry is +Inf)
	sum       uint64   // atomic float64 bits
	count     uint64   // atomic total count
}

// NewHistogram constructs an unregistered Histogram. upperBounds must
// be strictly increasing; the +Inf bucket is implicit.
func NewHistogram(name, help string, upperBounds []float64) *Histogram {
	for i := 1; i < len(upperBounds); i++ {
		if upperBounds[i] <= upperBounds[i-1] {
			panic(fmt.Sprintf("metrics: histogram %q bounds must be strictly increasing", name))
		}
	}
	return &Histogram{
		name:      name,
		help:      help,
		upper:     append([]float64{}, upperBounds...),
		bucketCnt: make([]uint64, len(upperBounds)+1), // one extra for +Inf
	}
}

// Observe records a single sample.
func (h *Histogram) Observe(v float64) {
	for i, up := range h.upper {
		if v <= up {
			atomic.AddUint64(&h.bucketCnt[i], 1)
		}
	}
	// Always increment the +Inf bucket (cumulative semantics).
	atomic.AddUint64(&h.bucketCnt[len(h.upper)], 1)
	atomic.AddUint64(&h.count, 1)
	for {
		old := atomic.LoadUint64(&h.sum)
		newSum := math.Float64frombits(old) + v
		if atomic.CompareAndSwapUint64(&h.sum, old, math.Float64bits(newSum)) {
			return
		}
	}
}

func (h *Histogram) writeTo(w *bufferedWriter) {
	w.writeMeta(h.name, h.help, typeHistogram)
	for i, up := range h.upper {
		labels := []labelPair{{"le", formatFloat(up)}}
		w.writeSample(h.name+"_bucket", labels, float64(atomic.LoadUint64(&h.bucketCnt[i])))
	}
	w.writeSample(h.name+"_bucket", []labelPair{{"le", "+Inf"}}, float64(atomic.LoadUint64(&h.bucketCnt[len(h.upper)])))
	w.writeSample(h.name+"_sum", nil, math.Float64frombits(atomic.LoadUint64(&h.sum)))
	w.writeSample(h.name+"_count", nil, float64(atomic.LoadUint64(&h.count)))
}

// -----------------------------------------------------------------------
// Labelled variants (vectors)
// -----------------------------------------------------------------------

// CounterVec is a family of counters indexed by a fixed set of label
// keys. Label values are provided per sample.
type CounterVec struct {
	name      string
	help      string
	labelKeys []string

	mu       sync.Mutex
	children map[string]*Counter
	keys     []string // insertion-ordered; stable for scrape ordering within a vec
}

// NewCounterVec constructs a vector counter. labelKeys must be non-
// empty; use NewCounter for an unlabelled counter.
func NewCounterVec(name, help string, labelKeys []string) *CounterVec {
	if len(labelKeys) == 0 {
		panic(fmt.Sprintf("metrics: counter vec %q needs at least one label key", name))
	}
	return &CounterVec{
		name:      name,
		help:      help,
		labelKeys: append([]string{}, labelKeys...),
		children:  map[string]*Counter{},
	}
}

// With returns the child counter for the given label values. Values
// are identified by the concatenation of label values; caller supplies
// them in the same order as labelKeys from NewCounterVec.
func (cv *CounterVec) With(values ...string) *Counter {
	if len(values) != len(cv.labelKeys) {
		panic(fmt.Sprintf("metrics: counter vec %q: got %d label values, want %d", cv.name, len(values), len(cv.labelKeys)))
	}
	key := joinLabelValues(values)
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if c, ok := cv.children[key]; ok {
		return c
	}
	c := &Counter{name: cv.name, help: cv.help}
	cv.children[key] = c
	cv.keys = append(cv.keys, key)
	return c
}

func (cv *CounterVec) writeTo(w *bufferedWriter) {
	w.writeMeta(cv.name, cv.help, typeCounter)
	cv.mu.Lock()
	keys := append([]string(nil), cv.keys...)
	childMap := make(map[string]*Counter, len(cv.children))
	for k, v := range cv.children {
		childMap[k] = v
	}
	cv.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		values := splitLabelValues(k)
		pairs := make([]labelPair, len(cv.labelKeys))
		for i, lk := range cv.labelKeys {
			pairs[i] = labelPair{key: lk, value: values[i]}
		}
		w.writeSample(cv.name, pairs, childMap[k].Value())
	}
}

// GaugeVec is the labelled variant of Gauge.
type GaugeVec struct {
	name      string
	help      string
	labelKeys []string

	mu       sync.Mutex
	children map[string]*Gauge
	keys     []string
}

// NewGaugeVec constructs a vector gauge.
func NewGaugeVec(name, help string, labelKeys []string) *GaugeVec {
	if len(labelKeys) == 0 {
		panic(fmt.Sprintf("metrics: gauge vec %q needs at least one label key", name))
	}
	return &GaugeVec{
		name:      name,
		help:      help,
		labelKeys: append([]string{}, labelKeys...),
		children:  map[string]*Gauge{},
	}
}

// With returns the child gauge for the given label values.
func (gv *GaugeVec) With(values ...string) *Gauge {
	if len(values) != len(gv.labelKeys) {
		panic(fmt.Sprintf("metrics: gauge vec %q: got %d label values, want %d", gv.name, len(values), len(gv.labelKeys)))
	}
	key := joinLabelValues(values)
	gv.mu.Lock()
	defer gv.mu.Unlock()
	if g, ok := gv.children[key]; ok {
		return g
	}
	g := &Gauge{name: gv.name, help: gv.help}
	gv.children[key] = g
	gv.keys = append(gv.keys, key)
	return g
}

func (gv *GaugeVec) writeTo(w *bufferedWriter) {
	w.writeMeta(gv.name, gv.help, typeGauge)
	gv.mu.Lock()
	keys := append([]string(nil), gv.keys...)
	childMap := make(map[string]*Gauge, len(gv.children))
	for k, v := range gv.children {
		childMap[k] = v
	}
	gv.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		values := splitLabelValues(k)
		pairs := make([]labelPair, len(gv.labelKeys))
		for i, lk := range gv.labelKeys {
			pairs[i] = labelPair{key: lk, value: values[i]}
		}
		w.writeSample(gv.name, pairs, childMap[k].Value())
	}
}

// -----------------------------------------------------------------------
// Internal exposition
// -----------------------------------------------------------------------

type labelPair struct {
	key, value string
}

type bufferedWriter struct {
	w   io.Writer
	err error
}

func newBufferedWriter(w io.Writer) *bufferedWriter {
	return &bufferedWriter{w: w}
}

func (bw *bufferedWriter) writef(format string, args ...any) {
	if bw.err != nil {
		return
	}
	if _, err := fmt.Fprintf(bw.w, format, args...); err != nil {
		bw.err = err
	}
}

func (bw *bufferedWriter) writeMeta(name, help string, typ metricType) {
	bw.writef("# HELP %s %s\n", name, escapeHelp(help))
	bw.writef("# TYPE %s %s\n", name, typ)
}

func (bw *bufferedWriter) writeSample(name string, labels []labelPair, value float64) {
	var sb strings.Builder
	sb.WriteString(name)
	if len(labels) > 0 {
		sb.WriteByte('{')
		for i, p := range labels {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(p.key)
			sb.WriteString(`="`)
			sb.WriteString(escapeLabel(p.value))
			sb.WriteByte('"')
		}
		sb.WriteByte('}')
	}
	bw.writef("%s %s\n", sb.String(), formatFloat(value))
}

func (bw *bufferedWriter) writeEOF() {
	bw.writef("# EOF\n")
}

// Label values are joined with an ASCII unit-separator so `a|b` and
// `ab|`  do not collide. Label values themselves cannot contain 0x1F
// (we would reject it in validation); joinLabelValues panics if
// someone smuggles one in.
const labelSep = "\x1f"

func joinLabelValues(vs []string) string {
	for _, v := range vs {
		if strings.Contains(v, labelSep) {
			panic("metrics: label value contains unit-separator")
		}
	}
	return strings.Join(vs, labelSep)
}

func splitLabelValues(k string) []string {
	return strings.Split(k, labelSep)
}

// formatFloat renders a float64 in OpenMetrics-friendly form: integer
// samples look integer, floats keep precision, NaN and infinities use
// the OpenMetrics tokens.
func formatFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return fmt.Sprintf("%d", int64(v))
	default:
		return fmt.Sprintf("%g", v)
	}
}

// escapeHelp replaces characters that break the HELP line format
// (newline, backslash). Strings the caller supplies are not attacker-
// controlled (they are developer literals), but defensive escaping
// keeps the scrape well-formed even if a future contributor gets
// creative.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// escapeLabel is stricter: OpenMetrics requires \\, \n, and \" inside
// double-quoted label values.
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// ErrNotRegistered can be returned by callers that look up a metric by
// name without finding it. Currently unused internally; kept for the
// external helper surface so test doubles can standardise on it.
var ErrNotRegistered = errors.New("metrics: not registered")

// -----------------------------------------------------------------------
// Process-wide default registry
// -----------------------------------------------------------------------

// defaultRegistry is the Registry the daemon shares across packages.
// Tests that need isolation should construct their own NewRegistry().
var defaultRegistry = NewRegistry()

// Default returns the process-wide Registry.
func Default() *Registry { return defaultRegistry }

// MustRegister is shorthand for Default().MustRegister.
func MustRegister(name string, c Collector) { defaultRegistry.MustRegister(name, c) }

// RegisterGaugeFunc is shorthand for Default().RegisterGaugeFunc.
func RegisterGaugeFunc(name, help string, fn func() float64) {
	defaultRegistry.RegisterGaugeFunc(name, help, fn)
}

// RegisterCounterFunc is shorthand for Default().RegisterCounterFunc.
func RegisterCounterFunc(name, help string, fn func() float64) {
	defaultRegistry.RegisterCounterFunc(name, help, fn)
}

// WriteOpenMetrics is shorthand for Default().WriteOpenMetrics.
func WriteOpenMetrics(w io.Writer) error {
	return defaultRegistry.WriteOpenMetrics(w)
}

// Collector is the type accepted by Registry.MustRegister. Exported
// so external packages have a name for the interface, even though the
// useful method on it is unexported (only metrics-package types can
// implement it, which is the intent).
type Collector = collectable

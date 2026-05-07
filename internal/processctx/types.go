// Package processctx maintains process context (PID/PPID/UID/account/exe/cmdline)
// for use enriching real-time security findings. The cache is bounded and
// LRU; the wire shape (ProcessContext) is materialized at serialization
// time by walking the PPID chain across the cache.
package processctx

import "time"

// processEntry is the cache shape. Flat. Parent linkage is by PPID, not
// by struct pointer, so an evicted intermediate parent cannot leave a
// dangling reference in another entry.
type processEntry struct {
	PID       int
	PPID      int
	UID       int
	UIDKnown  bool
	User      string
	Account   string
	Comm      string
	Exe       string
	Cmdline   []string
	StartedAt time.Time
	ProcRead  bool
	lastTouch time.Time
}

// ProcessContext is the wire/serialization shape. Built at read time by
// walking PPID up to a fixed depth and inlining whatever entries are still
// present in the cache. Omitted entirely from a Finding when nil.
type ProcessContext struct {
	PID       int             `json:"pid"`
	PPID      int             `json:"ppid"`
	UID       int             `json:"uid"`
	User      string          `json:"user,omitempty"`
	Account   string          `json:"account,omitempty"`
	Comm      string          `json:"comm,omitempty"`
	Exe       string          `json:"exe,omitempty"`
	Cmdline   []string        `json:"cmdline,omitempty"`
	StartedAt *time.Time      `json:"started_at,omitempty"`
	Parent    *ProcessContext `json:"parent,omitempty"`
}

// MaxParentDepth caps the parent chain walked during materialization.
// 5 is enough for php-fpm -> sh -> perl -> ncat -> connect chains and
// keeps JSON payloads small.
const MaxParentDepth = 5

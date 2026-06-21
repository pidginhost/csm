package checks

import (
	"sort"
	"time"
)

const (
	maxCatchUpBytes  = 8 << 20
	maxTrackedIPs    = 4096
	fingerprintBytes = 512
)

// followState is the persisted position+identity of the syslog follower.
// Populated by readNewSyslogLines (Task 2).
type followState struct {
	Offset    int64  `json:"offset"`
	HeadLen   int    `json:"head_len"`
	HeadFP    string `json:"head_fp"`
	AnchorLen int    `json:"anchor_len"`
	AnchorFP  string `json:"anchor_fp"`
}

// ftpFailTracker is the persisted detector state: where we last read to, and a
// per-IP sliding window of pure-ftpd auth-failure counts bucketed by minute.
type ftpFailTracker struct {
	Follow  followState              `json:"follow"`
	Buckets map[string]map[int64]int `json:"buckets"`
}

func newFTPFailTracker() *ftpFailTracker {
	return &ftpFailTracker{Buckets: map[string]map[int64]int{}}
}

func (t *ftpFailTracker) record(ip string, at time.Time) {
	if t.Buckets == nil {
		t.Buckets = map[string]map[int64]int{}
	}
	m := t.Buckets[ip]
	if m == nil {
		m = map[int64]int{}
		t.Buckets[ip] = m
	}
	m[at.Unix()/60]++
}

// evict drops minute buckets older than windowMin minutes and any IP left empty.
func (t *ftpFailTracker) evict(now time.Time, windowMin int) {
	cutoff := now.Unix()/60 - int64(windowMin)
	for ip, m := range t.Buckets {
		for minute := range m {
			if minute < cutoff {
				delete(m, minute)
			}
		}
		if len(m) == 0 {
			delete(t.Buckets, ip)
		}
	}
}

// capIPs bounds the tracked-IP set, evicting the IPs whose most-recent activity
// is oldest first (ties broken by IP string for deterministic tests).
func (t *ftpFailTracker) capIPs(max int) {
	if len(t.Buckets) <= max {
		return
	}
	type ipAge struct {
		ip     string
		recent int64
	}
	ages := make([]ipAge, 0, len(t.Buckets))
	for ip, m := range t.Buckets {
		var recent int64
		for minute := range m {
			if minute > recent {
				recent = minute
			}
		}
		ages = append(ages, ipAge{ip, recent})
	}
	sort.Slice(ages, func(i, j int) bool {
		if ages[i].recent != ages[j].recent {
			return ages[i].recent < ages[j].recent
		}
		return ages[i].ip < ages[j].ip
	})
	for i := 0; i < len(ages)-max; i++ {
		delete(t.Buckets, ages[i].ip)
	}
}

type ftpOffender struct {
	IP    string
	Count int
}

// offenders returns IPs whose summed failure count over the retained buckets is
// at least threshold, sorted by IP for stable output.
func (t *ftpFailTracker) offenders(threshold int) []ftpOffender {
	var out []ftpOffender
	for ip, m := range t.Buckets {
		sum := 0
		for _, c := range m {
			sum += c
		}
		if sum >= threshold {
			out = append(out, ftpOffender{ip, sum})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

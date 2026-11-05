package state

import "github.com/pidginhost/csm/internal/alert"

// BeginDelivery reserves eligible findings until finish is called with the
// successfully delivered subset. No store lock stays held during delivery.
// Receipts belong to the selected entry, so a scan clearing it while a send
// is in flight cannot be undone by that send's late completion. A finding
// with no entry, such as an action or a correlation-derived finding, gets
// one here.
//
// ponytail: action and correlation-derived findings exist only while
// produced. When the history reminder re-raises their source after more than
// 24h, they may be emailed once more. The upgrade path would be clearing
// derived rows through the latest merge.
func (s *Store) BeginDelivery(findings []alert.Finding) ([]alert.Finding, func([]alert.Finding)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if s.emailPending == nil {
		s.emailPending = make(map[string]*Entry)
	}
	type receipt struct {
		entry *Entry
		hash  string
	}
	selected := make(map[string]receipt)
	var eligible []alert.Finding
	for _, f := range s.filterUnemailedLocked(findings, now) {
		key := f.Key()
		entry := s.entries[key]
		if entry != nil && s.emailPending[key] == entry {
			continue
		}
		if entry == nil {
			entry = &Entry{Hash: f.Fingerprint(), FirstSeen: now, AlertSent: now}
			s.entries[key] = entry
		}
		entry.LastSeen = now
		s.dirty = true
		s.emailPending[key] = entry
		selected[key] = receipt{entry: entry, hash: f.Fingerprint()}
		eligible = append(eligible, f)
	}
	return eligible, func(delivered []alert.Finding) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, f := range delivered {
			key := f.Key()
			r, ok := selected[key]
			if ok && s.entries[key] == r.entry && f.Fingerprint() == r.hash {
				r.entry.Emailed = r.hash
				s.dirty = true
			}
		}
		for key, r := range selected {
			if s.emailPending[key] == r.entry {
				delete(s.emailPending, key)
			}
		}
	}
}

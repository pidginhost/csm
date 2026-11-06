package daemon

import "github.com/pidginhost/csm/internal/checks"

// maxTypoEdits is how far a login name can be from a real mailbox and still
// be that mailbox, counting local part and domain edits together.
const maxTypoEdits = 2

// editsWithin returns the optimal string alignment distance between a and b
// when it is at most k: an insert, delete, substitution or swap of adjacent
// bytes costs one, and no byte is edited twice. Equal leading bytes are always
// aligned, and each edit spends the budget, so the walk stays in the band k
// wide around the diagonal and gives up when the budget runs out.
//
// ponytail: branches four ways per edit, cheap at k = 2; a banded table if k
// ever grows.
func editsWithin(a, b string, k int) (int, bool) {
	if k <= 0 {
		return 0, k == 0 && a == b
	}
	for a != "" && b != "" && a[0] == b[0] {
		a, b = a[1:], b[1:]
	}
	if a == "" || b == "" {
		return len(a) + len(b), len(a)+len(b) <= k
	}
	if len(a)-len(b) > k || len(b)-len(a) > k {
		return 0, false
	}
	best, found := 0, false
	edit := func(x, y string) {
		if d, ok := editsWithin(x, y, k-1); ok {
			// Only a cheaper answer is worth finding from here on.
			best, found, k = d+1, true, d
		}
	}
	edit(a[1:], b[1:])
	edit(a[1:], b)
	edit(a, b[1:])
	if len(a) > 1 && len(b) > 1 && a[0] == b[1] && a[1] == b[0] {
		edit(a[2:], b[2:])
	}
	return best, found
}

// mailboxTypoIndex holds the hosted domains by byte length, the unresolved ones
// too: a domain within k edits differs in length by at most k. It is built with
// each snapshot and lookups only read it, so typed names add nothing to it.
type mailboxTypoIndex map[int][]string

func newMailboxTypoIndex(snapshot checks.HostingSnapshot) mailboxTypoIndex {
	index := mailboxTypoIndex{}
	for domain := range snapshot.Domains {
		index[len(domain)] = append(index[len(domain)], domain)
	}
	for domain := range snapshot.Unresolved {
		index[len(domain)] = append(index[len(domain)], domain)
	}
	return index
}

// typoMatch is the nearest real mailbox seen so far. Ties go to the smaller
// address, so the answer does not depend on the order of the scan.
type typoMatch struct {
	address string
	edits   int
}

// scan weighs the mailboxes of domain, the owner name among them, against
// local. domainEdits is what the domain already spent of maxTypoEdits.
func (m *typoMatch) scan(local, domain, owner string, locals []string, domainEdits int) {
	weigh := func(candidate string) {
		edits, near := editsWithin(local, candidate, maxTypoEdits-domainEdits)
		if !near {
			return
		}
		edits += domainEdits
		address := candidate + "@" + domain
		if m.address == "" || edits < m.edits || (edits == m.edits && address < m.address) {
			m.address, m.edits = address, edits
		}
	}
	for _, candidate := range locals {
		weigh(candidate)
	}
	weigh(owner)
}

// answer gives the match, or otherwise when nothing was near.
func (m *typoMatch) answer(otherwise sprayMailbox) sprayMailbox {
	if m.address == "" {
		return otherwise
	}
	// Truncating the real address would create a different mailbox key.
	if len(m.address) > maxSprayMailboxBytes {
		return sprayMailbox{name: otherwise.name, exist: mailboxExistenceUnknown}
	}
	return sprayMailbox{name: m.address, exist: mailboxExists}
}

// resolveTypo answers for a name no hosted domain lists as typed. The nearest
// mailbox within maxTypoEdits wins, whether on the typed domain, which is a
// candidate at no cost when hosted, or on a near hosted domain. A near domain
// whose mailboxes cannot be read might hold the mailbox meant, so it turns an
// answer of Missing into Unknown, but cannot outweigh a match. An extension
// name only reaches this on an unhosted domain, where it proves no absence.
func (r *cpanelMailboxResolver) resolveTypo(name, local, domain string) sprayMailbox {
	var nearest typoMatch
	otherwise := sprayMailbox{name: name, exist: mailboxMissing}
	if hasAddressExtension(local) {
		otherwise.exist = mailboxExistenceUnknown
	}
	// ponytail: linear in hosted domains of similar length for every name that
	// is not an exact match, under the mutex; a deletion-neighbourhood index if
	// a host with far more domains feels it.
	for size := len(domain) - maxTypoEdits; size <= len(domain)+maxTypoEdits; size++ {
		for _, candidate := range r.typoIndex[size] {
			domainEdits, near := editsWithin(domain, candidate, maxTypoEdits)
			if !near {
				continue
			}
			owner, resolved := r.snapshot.Domains[candidate]
			if !resolved {
				otherwise.exist = mailboxExistenceUnknown
				continue
			}
			lists, usable := r.accountLists(owner)
			if !usable {
				otherwise.exist = mailboxExistenceUnknown
				continue
			}
			nearest.scan(local, candidate, owner, lists[candidate], domainEdits)
		}
	}
	return nearest.answer(otherwise)
}

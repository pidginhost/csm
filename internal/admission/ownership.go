package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Owner is a verified victim identity: one hosting account at one inventory
// generation, or the shared host owner. Only an Inventory produces an
// account owner; the zero value is the host owner.
type Owner struct {
	account    string
	generation uint64
}

// HostOwner is the owner of unknown, multi-account and host-level evidence.
func HostOwner() Owner { return Owner{} }

func (o Owner) IsHost() bool       { return o.account == "" }
func (o Owner) Account() string    { return o.account }
func (o Owner) Generation() uint64 { return o.generation }

// Key is a stable text form: "host" or "acct:<name>#<generation>".
func (o Owner) Key() string {
	if o.IsHost() {
		return "host"
	}
	return "acct:" + o.account + "#" + strconv.FormatUint(o.generation, 10)
}

// Scope is the fairness unit: a verified owner and an action family.
type Scope struct {
	Owner  Owner
	Effect Effect
}

func (s Scope) Key() string { return s.Owner.Key() + "/" + s.Effect.String() }

// ClaimKind says where an ownership claim came from. Only server-owned
// context can verify an owner.
type ClaimKind uint8

const (
	// ClaimAccount names a hosting account from server-owned identity: a
	// process or file owner, or the account root a path lies under.
	ClaimAccount ClaimKind = iota + 1
	// ClaimDomain names the domain of the vhost or listener that served
	// the request, taken from server configuration or a per-vhost log.
	ClaimDomain
	// ClaimMailbox names a mailbox from a protocol exchange. The client
	// chose it, so it never verifies on its own.
	ClaimMailbox
	// ClaimRequestName names a host from request content such as a Host
	// header. It never verifies.
	ClaimRequestName
)

func (k ClaimKind) Valid() bool { return k >= ClaimAccount && k <= ClaimRequestName }

// Claim is an unverified statement of which account a piece of evidence
// concerns.
type Claim struct {
	Kind  ClaimKind `json:"kind"`
	Value string    `json:"value"`
}

// Inventory is an immutable snapshot of server-owned hosting accounts and
// the domains they serve.
type Inventory struct {
	accounts map[string]uint64
	domains  map[string]string
}

// ValidAccountName is the account-name alphabet the scan control protocol
// accepts, bounded to 64 bytes.
func ValidAccountName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func canonicalDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

// NewInventory copies accounts (name to generation) and domains (domain to
// owning account). Every generation is nonzero and every domain owner is a
// listed account.
func NewInventory(accounts map[string]uint64, domains map[string]string) (*Inventory, error) {
	inv := &Inventory{accounts: make(map[string]uint64, len(accounts)), domains: make(map[string]string, len(domains))}
	for name, gen := range accounts {
		if !ValidAccountName(name) || gen == 0 {
			return nil, errors.New("inventory account entry has an invalid name or zero generation")
		}
		inv.accounts[name] = gen
	}
	for domain, owner := range domains {
		d := canonicalDomain(domain)
		if d == "" || d != domain {
			return nil, errors.New("inventory domain is empty or not canonical")
		}
		if _, ok := inv.accounts[owner]; !ok {
			return nil, errors.New("inventory domain names an unlisted account")
		}
		inv.domains[d] = owner
	}
	return inv, nil
}

func (inv *Inventory) owner(account string) (Owner, bool) {
	gen, ok := inv.accounts[account]
	if !ok {
		return Owner{}, false
	}
	return Owner{account: account, generation: gen}, true
}

// Resolve verifies claims against the inventory. Claims that cannot be
// verified are ignored. Exactly one verified account yields that account;
// none, or several different accounts, yields the host owner.
func (inv *Inventory) Resolve(claims ...Claim) Owner {
	var found Owner
	for _, c := range claims {
		var o Owner
		var ok bool
		switch c.Kind {
		case ClaimAccount:
			o, ok = inv.owner(c.Value)
		case ClaimDomain:
			if account, hosted := inv.domains[canonicalDomain(c.Value)]; hosted {
				o, ok = inv.owner(account)
			}
		}
		if !ok {
			continue
		}
		if !found.IsHost() && found != o {
			return HostOwner()
		}
		found = o
	}
	return found
}

// Current reports whether o still names a present account at the same
// generation. The host owner is always current. Admission re-resolves
// owners with it before application.
func (inv *Inventory) Current(o Owner) bool {
	if o.IsHost() {
		return true
	}
	gen, ok := inv.accounts[o.account]
	return ok && gen == o.generation
}

// Generations assigns inventory generations. A name keeps its generation
// while it appears in consecutive complete observations with the same
// server-owned incarnation token; a name that disappears and returns, or
// returns with another token, gets a new one, so a recreated account never
// inherits the old account's scope, even when the replacement happened
// between two observations. A name observed without a token keeps its
// generation, and a stored name without one adopts the next token it is
// seen with. Generations are never reused. Initialize with NewGenerations
// or a successful UnmarshalBinary before observing or encoding; the zero
// value cannot allocate identities. It is not safe for concurrent use:
// callers must serialize every call.
type Generations struct {
	next         uint64
	live         map[string]uint64
	incarnations map[string]string
}

func NewGenerations() *Generations {
	return &Generations{next: 1, live: map[string]uint64{}, incarnations: map[string]string{}}
}

// maxIncarnationLen bounds one incarnation token.
const maxIncarnationLen = 64

func validIncarnation(token string) bool {
	if token == "" || len(token) > maxIncarnationLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}

// Observe records one complete inventory observation and returns the
// current name-to-generation map. incarnations maps listed names to their
// incarnation tokens; a name may have none. Callers must not pass a partial
// observation: a transient read failure would retire every missing account.
func (g *Generations) Observe(names []string, incarnations map[string]string) (map[string]uint64, error) {
	if g.next == 0 {
		return nil, errors.New("inventory generation tracker is not initialized")
	}
	present := make(map[string]bool, len(names))
	for _, name := range names {
		if !ValidAccountName(name) {
			return nil, errors.New("inventory observation has an invalid account name")
		}
		present[name] = true
	}
	for name, token := range incarnations {
		if !present[name] || !validIncarnation(token) {
			return nil, errors.New("inventory observation has an invalid incarnation")
		}
	}
	replaced := func(name string) bool {
		stored, observed := g.incarnations[name], incarnations[name]
		return stored != "" && observed != "" && stored != observed
	}
	newCount := uint64(0)
	for name := range present {
		if _, exists := g.live[name]; !exists || replaced(name) {
			newCount++
		}
	}
	if newCount > math.MaxUint64-g.next {
		return nil, errors.New("inventory generation counter is exhausted")
	}
	for name := range g.live {
		if !present[name] || replaced(name) {
			delete(g.live, name)
			delete(g.incarnations, name)
		}
	}
	sorted := make([]string, 0, len(present))
	for name := range present {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		if _, ok := g.live[name]; !ok {
			g.live[name] = g.next
			g.next++
		}
		if token := incarnations[name]; token != "" {
			g.incarnations[name] = token
		}
	}
	out := make(map[string]uint64, len(g.live))
	for name, gen := range g.live {
		out[name] = gen
	}
	return out, nil
}

type generationsRecord struct {
	V            int               `json:"v"`
	Next         uint64            `json:"next"`
	Live         map[string]uint64 `json:"live"`
	Incarnations map[string]string `json:"incarnations,omitempty"`
}

// A tracker without incarnation tokens keeps the version 1 encoding; one
// with them is version 2.
const (
	generationsVersion             = 1
	generationsIncarnationsVersion = 2
)

// MarshalBinary encodes the tracker as versioned JSON followed by an 8-byte
// SHA-256 prefix of that JSON.
func (g *Generations) MarshalBinary() ([]byte, error) {
	if g.next == 0 {
		return nil, errors.New("inventory generation tracker is not initialized")
	}
	rec := generationsRecord{V: generationsVersion, Next: g.next, Live: g.live}
	if len(g.incarnations) > 0 {
		rec.V, rec.Incarnations = generationsIncarnationsVersion, g.incarnations
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return append(body, sum[:8]...), nil
}

// UnmarshalBinary restores a tracker. Corrupt, unknown-version or
// inconsistent state is an error, never an empty tracker: an empty tracker
// would hand every account a fresh generation.
func (g *Generations) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("generations record is truncated")
	}
	body, sum := data[:len(data)-8], data[len(data)-8:]
	if want := sha256.Sum256(body); !bytes.Equal(sum, want[:8]) {
		return errors.New("generations record checksum mismatch")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var rec generationsRecord
	if err := dec.Decode(&rec); err != nil {
		return errors.New("generations record does not decode")
	}
	canonical, err := json.Marshal(rec)
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("generations record is not in canonical form")
	}
	if (rec.V != generationsVersion && rec.V != generationsIncarnationsVersion) || (rec.V == generationsIncarnationsVersion) != (len(rec.Incarnations) > 0) {
		return errors.New("generations record version is not supported")
	}
	if rec.Next == 0 {
		return errors.New("generations record has no next generation")
	}
	if rec.Live == nil {
		return errors.New("generations record has no inventory")
	}
	used := make(map[uint64]bool, len(rec.Live))
	for name, gen := range rec.Live {
		if !ValidAccountName(name) || gen == 0 || gen >= rec.Next || used[gen] {
			return errors.New("generations record has an invalid entry")
		}
		used[gen] = true
	}
	for name, token := range rec.Incarnations {
		if _, ok := rec.Live[name]; !ok || !validIncarnation(token) {
			return errors.New("generations record has an invalid incarnation")
		}
	}
	if rec.Incarnations == nil {
		rec.Incarnations = map[string]string{}
	}
	g.next, g.live, g.incarnations = rec.Next, rec.Live, rec.Incarnations
	return nil
}

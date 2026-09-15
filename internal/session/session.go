// Package session owns browser-session identities and their storage contract.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrInvalid = errors.New("invalid or expired browser session")
	ErrFull    = errors.New("browser session capacity reached; revoke unused sessions")
)

// MaxSessions bounds persisted browser state. Active sessions are never evicted
// to admit a new login.
const MaxSessions = 128

// Record is internal state. HTTP adapters must expose a separate public view;
// neither the verifier nor the login credential fingerprint belongs in it.
type Record struct {
	ID         string    `json:"id"`
	Verifier   string    `json:"verifier"`
	Credential string    `json:"credential"`
	Name       string    `json:"name"`
	Created    time.Time `json:"created"`
	LastSeen   time.Time `json:"last_seen"`
	Expires    time.Time `json:"expires"`
	RemoteIP   string    `json:"remote_ip"`
	UserAgent  string    `json:"user_agent"`
}

func (r Record) Valid(now time.Time, idle time.Duration) bool {
	return r.ID != "" && r.Verifier != "" && r.Credential != "" &&
		!r.Created.IsZero() && !now.Before(r.LastSeen) && !r.LastSeen.Before(r.Created) &&
		now.Before(r.Expires) && now.Before(r.LastSeen.Add(idle))
}

// Repository methods are atomic relative to revocation. Access must never
// recreate a record deleted by a concurrent logout. A failed commit is an error.
type Repository interface {
	ReplaceBrowserSession(Record, string, time.Time, time.Duration) error
	AccessBrowserSession(string, time.Time, time.Duration, bool) (Record, error)
	ListBrowserSessions(time.Time, time.Duration) ([]Record, error)
	RevokeBrowserSession(string) error
	ClearBrowserSessions() error
}

type Manager struct {
	repo     Repository
	lifetime time.Duration
	idle     time.Duration
}

// New starts one browser-session authority. Restart invalidates every existing
// browser session; API credentials have an independent lifecycle.
func New(repo Repository, lifetime, idle time.Duration) (*Manager, error) {
	if repo == nil || lifetime < time.Second || idle < time.Second || idle > lifetime {
		return nil, errors.New("invalid browser session store or policy")
	}
	if err := repo.ClearBrowserSessions(); err != nil {
		return nil, err
	}
	return &Manager{repo: repo, lifetime: lifetime, idle: idle}, nil
}

func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) Create(name, credential, previous, remoteIP, userAgent string, now time.Time) (string, Record, error) {
	if name == "" || credential == "" {
		return "", Record{}, ErrInvalid
	}
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return "", Record{}, err
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", Record{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes[:])
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	record := Record{ID: hex.EncodeToString(idBytes[:]), Verifier: Hash(secret), Credential: credential, Name: name,
		Created: now, LastSeen: now, Expires: now.Add(m.lifetime), RemoteIP: remoteIP, UserAgent: userAgent}
	previousHash := ""
	if previous != "" {
		previousHash = Hash(previous)
	}
	if err := m.repo.ReplaceBrowserSession(record, previousHash, now, m.idle); err != nil {
		return "", Record{}, err
	}
	return secret, record, nil
}

func (m *Manager) Access(secret string, now time.Time, touch bool) (Record, error) {
	if len(secret) != 43 {
		return Record{}, ErrInvalid
	}
	return m.repo.AccessBrowserSession(Hash(secret), now, m.idle, touch)
}
func (m *Manager) List(now time.Time) ([]Record, error) {
	return m.repo.ListBrowserSessions(now, m.idle)
}
func (m *Manager) Revoke(id string) error { return m.repo.RevokeBrowserSession(id) }
func (m *Manager) RevokeAll() error       { return m.repo.ClearBrowserSessions() }

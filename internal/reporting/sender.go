package reporting

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Transport selects how a report is signed for a target.
type Transport string

const (
	// TransportEd25519 signs with an Ed25519 node key (federation / central DB).
	TransportEd25519 Transport = "ed25519"
	// TransportHMAC signs with a shared HMAC secret (private collector).
	TransportHMAC Transport = "hmac"
)

// Target is one reporting destination.
type Target struct {
	Name      string
	URL       string
	Transport Transport
	NodeID    string
	KeyID     string
	// Ed25519Key is the node's private key for TransportEd25519.
	Ed25519Key ed25519.PrivateKey
	// HMACSecret is the shared secret for TransportHMAC.
	HMACSecret []byte
	// BearerToken is an optional Authorization bearer for HMAC collectors.
	BearerToken string
}

var (
	// ErrInsecureURL means a non-HTTPS target was configured for a non-loopback
	// host. Reports and their auth context must not cross the network in clear.
	ErrInsecureURL = errors.New("reporting: target URL must be https")
	// ErrRejected means the collector rejected the report (non-2xx, non-conflict).
	ErrRejected = errors.New("reporting: report rejected")
)

// Sender delivers a signed report body to a target over HTTP.
type Sender struct {
	client *http.Client
	now    func() time.Time
}

// NewSender builds a Sender. A nil client uses a default with a 15s timeout.
func NewSender(client *http.Client, now func() time.Time) *Sender {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &Sender{client: client, now: now}
}

// ValidateTargetURL reports whether raw is allowed for report delivery without
// logging or returning the raw URL.
func ValidateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !secureURL(u) {
		return ErrInsecureURL
	}
	return nil
}

// Send signs body for t and POSTs it. A 2xx is success; 409 Conflict (the
// collector already has this report) is treated as success. Other statuses and
// transport errors are failures the caller should retry from the spool.
func (s *Sender) Send(ctx context.Context, t Target, body []byte) error {
	u, err := url.Parse(t.URL)
	if err != nil {
		return fmt.Errorf("reporting: bad target url: %w", err)
	}
	if !secureURL(u) {
		return ErrInsecureURL
	}

	nonce, err := newNonce()
	if err != nil {
		return err
	}
	env := Envelope{
		NodeID:    t.NodeID,
		KeyID:     t.KeyID,
		Method:    http.MethodPost,
		Path:      requestPath(u),
		BodyHash:  HashBody(body),
		Timestamp: s.now().UTC().Unix(),
		Nonce:     nonce,
	}
	sig, scheme, err := s.sign(t, env)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSM-Node", env.NodeID)
	req.Header.Set("X-CSM-Key", env.KeyID)
	req.Header.Set("X-CSM-Timestamp", fmt.Sprintf("%d", env.Timestamp))
	req.Header.Set("X-CSM-Nonce", env.Nonce)
	req.Header.Set("X-CSM-Signature", scheme+"="+hex.EncodeToString(sig))
	if t.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.BearerToken)
	}

	resp, err := s.do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil // collector already recorded this report (replay/dup)
	default:
		return fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
}

func (s *Sender) do(req *http.Request) (*http.Response, error) {
	client := *s.client
	// The signature is bound to the configured URL path, and auth headers must
	// not be replayed to a redirected endpoint.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// The destination is an operator-configured report target, validated to
	// HTTPS (or loopback HTTP) by secureURL; it is not attacker-controlled.
	// #nosec G704 -- report target URL is operator config, scheme-validated.
	return client.Do(req)
}

func (s *Sender) sign(t Target, env Envelope) (sig []byte, scheme string, err error) {
	switch t.Transport {
	case TransportEd25519:
		sig, err = SignEd25519(env, t.Ed25519Key)
		return sig, "ed25519", err
	case TransportHMAC:
		sig, err = SignHMAC(env, t.HMACSecret)
		return sig, "sha256", err
	default:
		return nil, "", fmt.Errorf("reporting: unknown transport %q", t.Transport)
	}
}

// secureURL requires https, except for loopback hosts (local collectors / tests).
func secureURL(u *url.URL) bool {
	host := u.Hostname()
	if host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		if ip := net.ParseIP(host); ip != nil {
			return ip.IsLoopback()
		}
		return strings.EqualFold(host, "localhost")
	}
	return false
}

func requestPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

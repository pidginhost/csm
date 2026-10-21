package reporting

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxScoredSetBytes caps a pulled scored-set payload so a hostile or broken
// endpoint cannot exhaust memory.
const maxScoredSetBytes = 64 << 20 // 64 MiB

var (
	// ErrPullStatus means the endpoint returned an unexpected HTTP status.
	ErrPullStatus = errors.New("reporting: scored-set pull bad status")
	// ErrPullBodyTooLarge means the endpoint returned more bytes than a node
	// will verify and cache.
	ErrPullBodyTooLarge = errors.New("reporting: scored-set pull body too large")
	// ErrPullUnauthorized means the central service refused the node: it is not
	// enrolled and approved, its key is revoked, its clock is off, or the pull
	// was not signed.
	ErrPullUnauthorized = errors.New("reporting: scored-set pull unauthorized")
)

// Puller fetches and verifies the signed scored-set from the central service.
// It pulls a full snapshot on a cold cache and a one-step diff thereafter,
// verifying the Ed25519 signature before applying anything.
type Puller struct {
	client *http.Client
	url    string
	pubHex string
	// node signs each pull when set.
	node *Target
	now  func() time.Time
}

// NewPuller builds a Puller for setURL, verifying against the central public
// key (hex). A nil client uses a default with a 30s timeout.
func NewPuller(client *http.Client, setURL, pubHex string) *Puller {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Puller{client: client, url: setURL, pubHex: pubHex}
}

// NewSignedPuller builds a Puller that signs every pull with node's Ed25519
// key, as the central abuse database requires. node must use TransportEd25519.
// A nil now uses time.Now.
func NewSignedPuller(client *http.Client, setURL, pubHex string, node Target, now func() time.Time) *Puller {
	p := NewPuller(client, setURL, pubHex)
	if now == nil {
		now = time.Now
	}
	p.node, p.now = &node, now
	return p
}

// Refresh fetches an update relative to current and returns the new snapshot.
// When the endpoint reports no change (304), it returns current with
// changed=false. A diff that does not apply onto current (version gap) falls
// back by returning an error so the caller retries with a full pull (since=0).
func (p *Puller) Refresh(ctx context.Context, current ScoredSnapshot) (ScoredSnapshot, bool, error) {
	reqURL, err := pullURL(p.url, current.Version)
	if err != nil {
		return current, false, err
	}
	if validateErr := ValidateTargetURL(reqURL); validateErr != nil {
		return current, false, validateErr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return current, false, err
	}
	client := p.client
	if p.node != nil {
		if signErr := p.sign(req); signErr != nil {
			return current, false, signErr
		}
		// The signature is for this host and path, so never follow a redirect
		// with it. A copy keeps the shared client's own policy.
		c := *p.client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &c
	}
	// The scored-set URL is operator-configured (reputation.central.set_url) and
	// the response is Ed25519-verified before use; not attacker-controlled.
	// #nosec G704 -- central set URL is operator config, signature-verified.
	resp, err := client.Do(req)
	if err != nil {
		return current, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return current, false, nil
	case http.StatusUnauthorized:
		return current, false, ErrPullUnauthorized
	default:
		return current, false, ErrPullStatus
	}

	body, err := readScoredSetBody(resp.Body, maxScoredSetBytes)
	if err != nil {
		return current, false, err
	}
	sig, err := parseSetSignature(resp.Header.Get("X-CSM-Signature"))
	if err != nil {
		return current, false, err
	}

	switch resp.Header.Get("X-CSM-Kind") {
	case "diff":
		vd, err := OpenDiff(body, sig, p.pubHex)
		if err != nil {
			return current, false, err
		}
		next, err := ApplyDiff(current, vd)
		if err != nil {
			return current, false, err // version gap: caller retries full
		}
		return next, true, nil
	default: // "snapshot" or unset
		snap, err := OpenSnapshot(body, sig, p.pubHex)
		if err != nil {
			return current, false, err
		}
		return snap, true, nil
	}
}

func readScoredSetBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrPullBodyTooLarge
	}
	return body, nil
}

// pullURL drops any configured since for a full pull and sets exactly one for
// a warm pull. Other query parameters are kept.
func pullURL(base string, version uint64) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}
	q.Del("since")
	if version > 0 {
		q.Set("since", strconv.FormatUint(version, 10))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// sign adds the five node headers for a bodiless GET. The report target's
// bearer token is not sent.
func (p *Puller) sign(req *http.Request) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	env := Envelope{
		NodeID:    p.node.NodeID,
		KeyID:     p.node.KeyID,
		Method:    http.MethodGet,
		Path:      requestPath(req.URL),
		BodyHash:  HashBody(nil),
		Timestamp: p.now().UTC().Unix(),
		Nonce:     nonce,
	}
	sig, err := SignEd25519(env, p.node.Ed25519Key)
	if err != nil {
		return err
	}
	req.Header.Set("X-CSM-Node", env.NodeID)
	req.Header.Set("X-CSM-Key", env.KeyID)
	req.Header.Set("X-CSM-Timestamp", strconv.FormatInt(env.Timestamp, 10))
	req.Header.Set("X-CSM-Nonce", env.Nonce)
	req.Header.Set("X-CSM-Signature", "ed25519="+hex.EncodeToString(sig))
	return nil
}

func parseSetSignature(h string) ([]byte, error) {
	scheme, hexSig, ok := strings.Cut(h, "=")
	if !ok || scheme != "ed25519" {
		return nil, ErrSetSignature
	}
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		return nil, ErrSetSignature
	}
	return sig, nil
}

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
)

// Puller fetches and verifies the signed scored-set from the central service.
// It pulls a full snapshot on a cold cache and a one-step diff thereafter,
// verifying the Ed25519 signature before applying anything.
type Puller struct {
	client *http.Client
	url    string
	pubHex string
}

// NewPuller builds a Puller for setURL, verifying against the central public
// key (hex). A nil client uses a default with a 30s timeout.
func NewPuller(client *http.Client, setURL, pubHex string) *Puller {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Puller{client: client, url: setURL, pubHex: pubHex}
}

// Refresh fetches an update relative to current and returns the new snapshot.
// When the endpoint reports no change (304), it returns current with
// changed=false. A diff that does not apply onto current (version gap) falls
// back by returning an error so the caller retries with a full pull (since=0).
func (p *Puller) Refresh(ctx context.Context, current ScoredSnapshot) (ScoredSnapshot, bool, error) {
	reqURL := p.url
	var err error
	if current.Version > 0 {
		reqURL, err = withSince(p.url, current.Version)
		if err != nil {
			return current, false, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return current, false, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return current, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return current, false, nil
	}
	if resp.StatusCode != http.StatusOK {
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

func withSince(base string, version uint64) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}
	q.Set("since", strconv.FormatUint(version, 10))
	u.RawQuery = q.Encode()
	return u.String(), nil
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

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

// ErrPullStatus means the endpoint returned an unexpected HTTP status.
var ErrPullStatus = errors.New("reporting: scored-set pull bad status")

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
	if current.Version > 0 {
		reqURL = withSince(p.url, current.Version)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScoredSetBytes))
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

func withSince(base string, version uint64) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set("since", strconv.FormatUint(version, 10))
	u.RawQuery = q.Encode()
	return u.String()
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

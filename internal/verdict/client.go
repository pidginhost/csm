// Package verdict implements an HMAC-signed HTTP client for the
// auto_response.verdict_callback hook. CSM POSTs a Request to the panel
// URL before each automatic block; the panel's Response is advisory
// (block / allow / "" -> block default; tenant_id is logged). Errors are
// fail-open: the caller (firewall.Engine.BlockIP) proceeds with the
// default block on any callback failure.
package verdict

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	verdictMaxResponseBytes = 64 << 10 // 64 KB - verdict response is small JSON
	// verdictMaxResponseSkew bounds how far the panel's reply timestamp
	// may drift from CSM's clock. Anything older or further into the
	// future is treated as a replayed or forged response.
	verdictMaxResponseSkew = 5 * time.Minute
)

// Config configures the verdict callback client. HMACSecretEnv (if set)
// is consulted at every Ask call so operators can rotate via env without
// restarting the daemon.
//
// RequireResponseSignature controls whether the panel must sign its
// response body with the same HMAC scheme used on the request
// (X-CSM-Signature header). Default is true: when a secret is configured,
// CSM rejects unsigned or forged responses to prevent an on-path attacker
// from silently downgrading a block to "allow". Set the pointer to a
// false value only during phpanel-side rollouts that have not yet
// implemented response signing. When no HMAC secret is configured at all,
// response signing is skipped because there is no key to verify against.
type Config struct {
	URL                      string
	HMACSecret               string
	HMACSecretEnv            string
	RequireResponseSignature *bool
	Timeout                  time.Duration
}

// requireResponseSig returns the effective response-signature requirement,
// defaulting to true (secure by default) when the operator did not set
// an explicit value.
func (c Config) requireResponseSig() bool {
	if c.RequireResponseSignature == nil {
		return true
	}
	return *c.RequireResponseSignature
}

// Request is what CSM asks the panel about. Ask sets Nonce and Timestamp
// for every exchange. They bind each request to its own reply so an
// attacker cannot replay an old "allow" verdict.
type Request struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Severity  string `json:"severity,omitempty"`
	Source    string `json:"source,omitempty"` // "auto_response" | "manual"
	Nonce     string `json:"nonce,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// Response is what the panel may answer.
//
//	verdict    = "block" - CSM proceeds with its default action.
//	verdict    = "allow" - CSM logs the verdict but does NOT block.
//	verdict    = "" or missing - equivalent to "block" (default).
//	tenant_id  = optional attribution string CSM logs alongside the decision.
//	nonce      = MUST equal the Request.Nonce. Required when response
//	             signing is in effect; defeats replay of captured replies.
//	timestamp  = unix seconds the panel produced the reply. MUST be
//	             within verdictMaxResponseSkew of CSM's clock.
type Response struct {
	Verdict   string `json:"verdict,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	Note      string `json:"note,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// Client posts each block decision to the configured URL and reads the
// (advisory) response. Timeouts and 5xx are returned as errors - the
// caller decides whether to fail open (allow CSM to proceed) or closed.
type Client struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &Client{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}
}

// resolveSecret reads HMACSecretEnv at call time, falling back to the
// static secret. Lets operators rotate via env without daemon restart.
func (c *Client) resolveSecret() string {
	if c.cfg.HMACSecretEnv != "" {
		if v := os.Getenv(c.cfg.HMACSecretEnv); v != "" {
			return v
		}
	}
	return c.cfg.HMACSecret
}

// verifyResponseSignature checks that header carries a well-formed
// X-CSM-Signature header (sha256=<hex>) over body, computed with secret.
// Returns a descriptive error on missing, malformed, or mismatched values
// using a constant-time comparison.
func verifyResponseSignature(secret string, body []byte, header string) error {
	if header == "" {
		return fmt.Errorf("verdict callback response missing signature header (X-CSM-Signature)")
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return fmt.Errorf("verdict callback response signature has unsupported algorithm")
	}
	gotHex := strings.TrimPrefix(header, prefix)
	got, err := hex.DecodeString(gotHex)
	if err != nil {
		return fmt.Errorf("verdict callback response signature is not valid hex")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("verdict callback response signature mismatch")
	}
	return nil
}

// Ask POSTs the request, returns the panel's response or an error.
func (c *Client) Ask(ctx context.Context, req Request) (Response, error) {
	// Defense-in-depth URL check (config validation already ran at load,
	// this re-check defends against misconfiguration via cfg corruption).
	rawURL := strings.TrimSpace(c.cfg.URL)
	if rawURL == "" {
		return Response{}, fmt.Errorf("verdict callback URL not configured")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Response{}, fmt.Errorf("verdict callback URL parse: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Response{}, fmt.Errorf("verdict callback URL must use http or https")
	}
	if parsed.Host == "" {
		return Response{}, fmt.Errorf("verdict callback URL must include host")
	}

	nonce, err := newNonce()
	if err != nil {
		return Response{}, fmt.Errorf("verdict callback nonce generation: %w", err)
	}
	req.Nonce = nonce
	req.Timestamp = time.Now().Unix()
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	secret := c.resolveSecret()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		r.Header.Set("X-CSM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := c.client.Do(r)
	if err != nil {
		return Response{}, fmt.Errorf("verdict callback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "verdict callback: HTTP %d for %s\n", resp.StatusCode, req.IP)
		return Response{}, fmt.Errorf("verdict callback HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, verdictMaxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("verdict callback read: %w", err)
	}
	if int64(len(data)) > verdictMaxResponseBytes {
		return Response{}, fmt.Errorf("verdict callback response exceeds %d bytes", verdictMaxResponseBytes)
	}
	if secret != "" && c.cfg.requireResponseSig() {
		// Verify the panel signed its response with the same secret used
		// on the request. Without this check a network attacker could
		// downgrade block to allow on every call. Rejecting the reply keeps
		// the engine on its default block path.
		if err := verifyResponseSignature(secret, data, resp.Header.Get("X-CSM-Signature")); err != nil {
			return Response{}, err
		}
	}
	if strings.TrimSpace(string(data)) == "" {
		return Response{}, nil
	}
	var out Response
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&out); err != nil {
		return Response{}, fmt.Errorf("verdict callback decode: %w", err)
	}
	var trailing struct{}
	if err := dec.Decode(&trailing); err != io.EOF {
		return Response{}, fmt.Errorf("verdict callback decode: trailing JSON")
	}
	// Validate response shape. Unknown verdict strings are rejected
	// defensively rather than silently treated as "block".
	if out.Verdict != "" && out.Verdict != "block" && out.Verdict != "allow" {
		return Response{}, fmt.Errorf("verdict callback returned unknown verdict %q", out.Verdict)
	}
	// Replay protection: when response signing is enforced, the panel
	// must echo the request nonce and stamp a timestamp inside the
	// allowed skew. Without these checks a captured "allow" reply
	// could be replayed against a fresh request.
	if secret != "" && c.cfg.requireResponseSig() {
		if subtle.ConstantTimeCompare([]byte(out.Nonce), []byte(req.Nonce)) != 1 {
			return Response{}, fmt.Errorf("verdict callback response nonce mismatch")
		}
		if out.Timestamp == 0 {
			return Response{}, fmt.Errorf("verdict callback response missing timestamp")
		}
		drift := time.Since(time.Unix(out.Timestamp, 0))
		if drift < 0 {
			drift = -drift
		}
		if drift > verdictMaxResponseSkew {
			return Response{}, fmt.Errorf("verdict callback response timestamp drift %s exceeds %s", drift, verdictMaxResponseSkew)
		}
	}
	return out, nil
}

// newNonce returns a fresh 128-bit hex nonce. crypto/rand is the only
// acceptable source: math/rand would let an attacker who observes one
// nonce predict the next and craft a replay reply in advance.
func newNonce() (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

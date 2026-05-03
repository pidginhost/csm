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
	"crypto/sha256"
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

const verdictMaxResponseBytes = 64 << 10 // 64 KB - verdict response is small JSON

// Config configures the verdict callback client. HMACSecretEnv (if set)
// is consulted at every Ask call so operators can rotate via env without
// restarting the daemon.
type Config struct {
	URL           string
	HMACSecret    string
	HMACSecretEnv string
	Timeout       time.Duration
}

// Request is what CSM asks the panel about.
type Request struct {
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Severity string `json:"severity,omitempty"`
	Source   string `json:"source,omitempty"` // "auto_response" | "manual"
}

// Response is what the panel may answer.
//
//	verdict   = "block" - CSM proceeds with its default action.
//	verdict   = "allow" - CSM logs the verdict but does NOT block.
//	verdict   = "" or missing - equivalent to "block" (default).
//	tenant_id = optional attribution string CSM logs alongside the decision.
type Response struct {
	Verdict  string `json:"verdict,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Note     string `json:"note,omitempty"`
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

// Ask POSTs the request, returns the panel's response or an error.
func (c *Client) Ask(ctx context.Context, req Request) (Response, error) {
	// Defense-in-depth URL check (config validation already ran at load,
	// this re-check defends against misconfiguration via cfg corruption).
	if strings.TrimSpace(c.cfg.URL) == "" {
		return Response{}, fmt.Errorf("verdict callback URL not configured")
	}
	parsed, err := url.Parse(c.cfg.URL)
	if err != nil {
		return Response{}, fmt.Errorf("verdict callback URL parse: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Response{}, fmt.Errorf("verdict callback URL must use http or https")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if secret := c.resolveSecret(); secret != "" {
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
	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, verdictMaxResponseBytes)).Decode(&out); err != nil {
		return Response{}, fmt.Errorf("verdict callback decode: %w", err)
	}
	// Validate response shape. Unknown verdict strings are rejected
	// defensively rather than silently treated as "block".
	if out.Verdict != "" && out.Verdict != "block" && out.Verdict != "allow" {
		return Response{}, fmt.Errorf("verdict callback returned unknown verdict %q", out.Verdict)
	}
	return out, nil
}

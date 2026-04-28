package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CaptchaProvider verifies a third-party CAPTCHA token. Implementations
// post the operator's secret + the visitor's response token to the
// provider's siteverify endpoint and return a single bool: did the
// provider accept this submission?
type CaptchaProvider interface {
	Name() string
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// providerEndpoint is exposed as a package var so tests can point a
// provider at httptest.Server rather than the live siteverify URL.
var providerEndpoint = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"hcaptcha":  "https://hcaptcha.com/siteverify",
}

// captchaProvider implements both Cloudflare Turnstile and hCaptcha;
// they accept identical request/response shapes (POST form, JSON
// {"success":bool} reply) so a single struct covers both.
type captchaProvider struct {
	name     string
	endpoint string
	secret   string
	client   *http.Client
}

// NewCaptchaProvider returns the right provider for the configured
// name. Returns nil + nil when the operator has not enabled CAPTCHA;
// the server treats nil as "feature off".
func NewCaptchaProvider(name, secret string, timeout time.Duration) (CaptchaProvider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil, nil
	}
	endpoint, ok := providerEndpoint[name]
	if !ok {
		return nil, fmt.Errorf("unknown captcha provider %q (want turnstile or hcaptcha)", name)
	}
	if secret == "" {
		return nil, fmt.Errorf("captcha provider %q requires secret_key", name)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &captchaProvider{
		name:     name,
		endpoint: endpoint,
		secret:   secret,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

func (p *captchaProvider) Name() string { return p.name }

// Verify posts the operator's secret + the visitor's token to the
// provider. The remoteIP is optional but recommended; both Turnstile
// and hCaptcha accept it for binding the verification to a single
// client. Network errors propagate; a 200 with success=false returns
// (false, nil).
func (p *captchaProvider) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if token == "" {
		return false, errors.New("empty captcha token")
	}
	form := url.Values{}
	form.Set("secret", p.secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("building siteverify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("siteverify call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("siteverify status %d", resp.StatusCode)
	}

	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("decoding siteverify response: %w", err)
	}
	return body.Success, nil
}

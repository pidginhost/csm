// Package stalwartapi is a small client for the Stalwart 1.0 admin API: the
// JMAP "x:" methods CSM uses to read and change Stalwart's settings.
package stalwartapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxResponse bounds every response body CSM reads from Stalwart.
const maxResponse = 4 << 20

var using = []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}

// ErrUnauthorized means Stalwart refused the admin login.
var ErrUnauthorized = errors.New("stalwart refused the admin login")

// MethodError is a JMAP method failure, or one failed entry of a set call.
type MethodError struct {
	Method      string
	Type        string
	Description string
}

func (e *MethodError) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("stalwart %s: %s", e.Method, e.Type)
	}
	return fmt.Sprintf("stalwart %s: %s: %s", e.Method, e.Type, e.Description)
}

// Client talks to one Stalwart server as one admin. Errors name the method
// and URL path only, never the login.
type Client struct {
	base     string
	user     string
	password string
	hc       *http.Client

	mu      sync.Mutex
	account string
}

// New returns a client for the Stalwart server at baseURL.
func New(baseURL, user, password string) *Client {
	base := strings.TrimRight(baseURL, "/")
	return &Client{
		base:     base,
		user:     user,
		password: password,
		hc: &http.Client{
			Timeout: 30 * time.Second,
			// The session and its redirects name Stalwart's public hostname.
			// CSM talks to the address it was given and nowhere else.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 || req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme || req.URL.User != nil {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if err := ValidateURL(c.base); err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, fmt.Errorf("stalwart %s: bad API address", path)
	}
	req.SetBasicAuth(c.user, c.password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("stalwart %s: %w", path, c.redactError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("stalwart %s: %w", path, ErrUnauthorized)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stalwart %s: HTTP %d", path, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("stalwart %s: reading response: %w", path, c.redactError(err))
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("stalwart %s: response larger than %d bytes", path, maxResponse)
	}
	return data, nil
}

// accountID reads the admin account id from the session document once.
func (c *Client) accountID(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.account != "" {
		return c.account, nil
	}
	const path = "/.well-known/jmap"
	data, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	var session struct {
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		return "", fmt.Errorf("stalwart %s: not a JMAP session", path)
	}
	id := session.PrimaryAccounts["urn:stalwart:jmap"]
	if id == "" {
		return "", fmt.Errorf("stalwart %s: no admin account; is this Stalwart 1.0 or later?", path)
	}
	c.account = id
	return id, nil
}

// call sends one method call and returns its response arguments.
func (c *Client) call(ctx context.Context, method string, args map[string]any) (json.RawMessage, error) {
	account, err := c.accountID(ctx)
	if err != nil {
		return nil, err
	}
	full := map[string]any{"accountId": account}
	for k, v := range args {
		full[k] = v
	}
	body, err := json.Marshal(map[string]any{
		"using":       using,
		"methodCalls": []any{[]any{method, full, "a"}},
	})
	if err != nil {
		return nil, err
	}
	data, err := c.do(ctx, http.MethodPost, "/jmap/", body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(data, &resp); err != nil || len(resp.MethodResponses) != 1 || len(resp.MethodResponses[0]) != 3 {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	var name string
	if err := json.Unmarshal(resp.MethodResponses[0][0], &name); err != nil {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	out := resp.MethodResponses[0][1]
	if name == "error" {
		me := &MethodError{Method: method}
		var e struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		_ = json.Unmarshal(out, &e)
		me.Type, me.Description = Redact(e.Type, c.user, c.password), Redact(e.Description, c.user, c.password)
		return nil, me
	}
	if name != method {
		return nil, fmt.Errorf("stalwart %s: answered as %s", method, Redact(name, c.user, c.password))
	}
	return out, nil
}

// set sends a /set call and turns its first failed entry into a MethodError.
func (c *Client) set(ctx context.Context, method string, args map[string]any) (json.RawMessage, error) {
	out, err := c.call(ctx, method, args)
	if err != nil {
		return nil, err
	}
	var res struct {
		Created      map[string]*struct{}  `json:"created"`
		Updated      map[string]*struct{}  `json:"updated"`
		NotCreated   map[string]setFailure `json:"notCreated"`
		NotUpdated   map[string]setFailure `json:"notUpdated"`
		NotDestroyed map[string]setFailure `json:"notDestroyed"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	for _, failed := range []map[string]setFailure{res.NotCreated, res.NotUpdated, res.NotDestroyed} {
		for _, f := range failed {
			return nil, &MethodError{Method: method, Type: Redact(f.Type, c.user, c.password), Description: Redact(f.Description, c.user, c.password)}
		}
	}
	for operation, acknowledged := range map[string]map[string]*struct{}{"create": res.Created, "update": res.Updated} {
		if requested, ok := args[operation].(map[string]any); ok {
			for id := range requested {
				if value, ok := acknowledged[id]; !ok || (operation == "create" && value == nil) {
					return nil, fmt.Errorf("stalwart %s: write was not acknowledged", method)
				}
			}
		}
	}
	return out, nil
}

type setFailure struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// get sends a /get call and decodes its list into dst.
func (c *Client) get(ctx context.Context, method string, ids []string, dst any) error {
	args := map[string]any{"ids": nil}
	if ids != nil {
		args["ids"] = ids
	}
	out, err := c.call(ctx, method, args)
	if err != nil {
		return err
	}
	var res struct {
		List json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal(out, &res); err != nil || len(res.List) == 0 || bytes.Equal(bytes.TrimSpace(res.List), []byte("null")) {
		return fmt.Errorf("stalwart %s: unexpected response", method)
	}
	if err := json.Unmarshal(res.List, dst); err != nil {
		return fmt.Errorf("stalwart %s: unexpected response: %w", method, c.redactError(err))
	}
	return nil
}

// getSingleton reads the one object of a singleton type into dst.
func (c *Client) getSingleton(ctx context.Context, method string, dst any) error {
	var list []json.RawMessage
	if err := c.get(ctx, method, []string{"singleton"}, &list); err != nil {
		return err
	}
	if len(list) != 1 || bytes.Equal(bytes.TrimSpace(list[0]), []byte("null")) {
		return fmt.Errorf("stalwart %s: settings object not found", method)
	}
	if err := json.Unmarshal(list[0], dst); err != nil {
		return fmt.Errorf("stalwart %s: unexpected response: %w", method, c.redactError(err))
	}
	return nil
}

func (c *Client) updateSingleton(ctx context.Context, method string, patch map[string]any) error {
	_, err := c.set(ctx, method, map[string]any{"update": map[string]any{"singleton": patch}})
	return err
}

// Redact removes the login's password and its common wire encodings from
// diagnostics, including server-provided text.
func Redact(text, user, password string) string {
	if password == "" {
		return text
	}
	for _, value := range []string{base64.StdEncoding.EncodeToString([]byte(user + ":" + password)), url.QueryEscape(password), url.PathEscape(password), password} {
		text = strings.ReplaceAll(text, value, "[redacted]")
	}
	return text
}

// LocalURL reports whether the API address explicitly names loopback. Only
// a local API can use this daemon's firewall as proof of listener protection.
func LocalURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.Unmap().IsLoopback()
}

// ValidateURL rejects credentials, queries and fragments in API bases, and requires TLS
// when Basic authentication leaves this host. Errors never echo the address.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("stalwart API address must be an http or https address")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("stalwart API address must not contain a login, query or fragment")
	}
	if u.Scheme == "http" && !LocalURL(raw) {
		return errors.New("stalwart API address must use https unless it is on this host")
	}
	return nil
}

func (c *Client) redactError(err error) error {
	message := Redact(err.Error(), c.user, c.password)
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

package stalwartapi

import (
	"context"
	"errors"
	"maps"
	"net"
	"os"
	"testing"
)

// TestSmokeBlocklistProbe sends the blocklist probe to a real, throwaway
// Stalwart. It skips unless CSM_STALWART_SMOKE_URL names one; STALWART_USER
// and STALWART_PASSWORD carry its admin login.
func TestSmokeBlocklistProbe(t *testing.T) {
	url := os.Getenv("CSM_STALWART_SMOKE_URL")
	if url == "" {
		t.Skip("CSM_STALWART_SMOKE_URL is not set")
	}
	c := New(url, os.Getenv("STALWART_USER"), os.Getenv("STALWART_PASSWORD"))
	got, err := c.ClassifySpam(context.Background(), BlocklistProbe)
	if err != nil {
		t.Fatalf("ClassifySpam: %v", err)
	}
	if got.Result == "" {
		t.Fatal("the probe returned no result")
	}
	t.Logf("score %v, result %s, tags %q", got.Score, got.Result, got.Tags)
}

// TestSmokeKeyLogin logs in with API keys of the admin account on a real,
// throwaway Stalwart. It also needs CSM_STALWART_SMOKE_CLIENT_IP, the address
// Stalwart sees this test connect from.
func TestSmokeKeyLogin(t *testing.T) {
	url := os.Getenv("CSM_STALWART_SMOKE_URL")
	if url == "" {
		t.Skip("CSM_STALWART_SMOKE_URL is not set")
	}
	clientIP := os.Getenv("CSM_STALWART_SMOKE_CLIENT_IP")
	if clientIP == "" {
		t.Skip("CSM_STALWART_SMOKE_CLIENT_IP is not set")
	}
	ctx := context.Background()
	admin := New(url, os.Getenv("STALWART_USER"), os.Getenv("STALWART_PASSWORD"))
	owner, found, err := admin.AccountByAddress(ctx, "admin@example.org")
	if err != nil || !found {
		t.Fatalf("AccountByAddress(admin) = %v, %v", found, err)
	}
	// Docker's proxy holds the published port, which the production peer
	// check refuses.
	anyPeer := func(context.Context, net.Conn) error { return nil }

	_, local, err := admin.CreateAPIKey(ctx, owner.ID, "CSM smoke test", []string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if _, err = NewKey(url, local, anyPeer).SessionAccount(ctx); !errors.Is(err, ErrForbidden) {
		t.Fatalf("key for other addresses: %v, want ErrForbidden", err)
	}

	id, secret, err := admin.CreateAPIKey(ctx, owner.ID, "CSM smoke test", []string{clientIP})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	key := NewKey(url, secret, anyPeer)
	got, err := key.SessionAccount(ctx)
	if err != nil || got != owner.ID {
		t.Fatalf("key session account = %q, %v; want the key's owner %q", got, err, owner.ID)
	}
	smokeLookupKeys(ctx, t, key)
	if err = admin.DeleteAPIKeys(ctx, owner.ID, []string{id}); err != nil {
		t.Fatalf("DeleteAPIKeys: %v", err)
	}
	if _, err = NewKey(url, secret, anyPeer).SessionAccount(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("destroyed key: %v, want ErrUnauthorized", err)
	}
}

// smokeLookupKeys creates, lists and deletes lookup keys through c.
func smokeLookupKeys(ctx context.Context, t *testing.T, c *Client) {
	t.Helper()
	const ns = "csm-smoke"
	if err := c.CreateLookupKeys(ctx, ns, []string{"203.0.113.9", "198.51.100.*"}); err != nil {
		t.Fatalf("CreateLookupKeys: %v", err)
	}
	keys, err := c.LookupKeys(ctx, ns)
	if err != nil {
		t.Fatalf("LookupKeys: %v", err)
	}
	globs := map[string]bool{}
	var ids []string
	for _, k := range keys {
		globs[k.Key] = k.Glob
		ids = append(ids, k.ID)
	}
	if want := map[string]bool{"203.0.113.9": false, "198.51.100.*": true}; !maps.Equal(globs, want) || len(keys) != 2 {
		t.Fatalf("LookupKeys = %+v, want %v", keys, want)
	}
	if err = c.DeleteLookupKeys(ctx, ids); err != nil {
		t.Fatalf("DeleteLookupKeys: %v", err)
	}
	if err = c.ReloadLookupStores(ctx); err != nil {
		t.Fatalf("ReloadLookupStores: %v", err)
	}
	if keys, err = c.LookupKeys(ctx, ns); err != nil || len(keys) != 0 {
		t.Fatalf("after delete LookupKeys = %+v, %v; want none", keys, err)
	}
	t.Logf("lookup keys: created, listed %d with glob flags, deleted, reloaded", len(ids))
}

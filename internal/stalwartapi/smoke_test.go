package stalwartapi

import (
	"context"
	"errors"
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
	got, err := NewKey(url, secret, anyPeer).SessionAccount(ctx)
	if err != nil || got != owner.ID {
		t.Fatalf("key session account = %q, %v; want the key's owner %q", got, err, owner.ID)
	}
	if err = admin.DeleteAPIKeys(ctx, owner.ID, []string{id}); err != nil {
		t.Fatalf("DeleteAPIKeys: %v", err)
	}
	if _, err = NewKey(url, secret, anyPeer).SessionAccount(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("destroyed key: %v, want ErrUnauthorized", err)
	}
}

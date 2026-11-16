package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

func TestDaemonStalwartClientChecksPeer(t *testing.T) {
	t.Cleanup(stalwartapi.SetKeyFileOwnerForTest(uint32(os.Getuid())))
	cfg := &config.Config{}
	cfg.Stalwart.APIURL = "http://127.0.0.1:8080"
	cfg.Stalwart.APIKeyFile = filepath.Join(t.TempDir(), "stalwart-api.key")

	var gotURL, gotKey string
	var gotCheck func(context.Context, net.Conn) error
	calls := 0
	old := newStalwartKeyClient
	newStalwartKeyClient = func(url, key string, check func(context.Context, net.Conn) error) *stalwartapi.Client {
		calls++
		gotURL, gotKey, gotCheck = url, key, check
		return stalwartapi.NewKey(url, key, check)
	}
	t.Cleanup(func() { newStalwartKeyClient = old })

	if stalwartKeyPresent(cfg) {
		t.Fatal("key reported present before the file exists")
	}
	if c, err := stalwartClient(cfg); !errors.Is(err, stalwartapi.ErrNoKeyFile) || c != nil {
		t.Fatalf("no key file: client %v, err %v; want ErrNoKeyFile", c, err)
	}
	if calls != 0 {
		t.Fatalf("constructor called %d times without a key file", calls)
	}

	if err := stalwartapi.WriteKeyFile(cfg.Stalwart.APIKeyFile, "test-key-1"); err != nil {
		t.Fatal(err)
	}
	if !stalwartKeyPresent(cfg) {
		t.Fatal("key reported absent after the file was written")
	}
	c, err := stalwartClient(cfg)
	if err != nil || c == nil {
		t.Fatalf("client %v, err %v", c, err)
	}
	if calls != 1 || gotURL != cfg.Stalwart.APIURL || gotKey != "test-key-1" {
		t.Fatalf("constructor got url %q key %q after %d calls", gotURL, gotKey, calls)
	}
	if gotCheck == nil || reflect.ValueOf(gotCheck).Pointer() != reflect.ValueOf(stalwartapi.CheckPeer).Pointer() {
		t.Fatal("constructor did not get the Stalwart peer check")
	}

	// A rotated key is used without a restart.
	if err := stalwartapi.WriteKeyFile(cfg.Stalwart.APIKeyFile, "test-key-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := stalwartClient(cfg); err != nil || gotKey != "test-key-2" {
		t.Fatalf("after rotation: key %q, err %v", gotKey, err)
	}
}

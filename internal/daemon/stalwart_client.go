package daemon

import (
	"context"
	"os"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

// stalwartAPI is the part of the Stalwart client the daemon acts through.
type stalwartAPI interface {
	AccountByAddress(ctx context.Context, address string) (stalwartapi.Account, bool, error)
	Account(ctx context.Context, id string) (stalwartapi.Account, bool, error)
	DisableSignIn(ctx context.Context, a stalwartapi.Account) error
	EnableSignIn(ctx context.Context, id string) error
	BlockedIPs(ctx context.Context, address string) ([]stalwartapi.BlockedIP, error)
	DeleteBlockedIPs(ctx context.Context, ids []string) error
	ReloadBlockedIPs(ctx context.Context) error
	SpamSettings(ctx context.Context) (stalwartapi.SpamSettings, error)
	SpamFilterStageOff(ctx context.Context) (bool, error)
	SpamRule(ctx context.Context, name string) (stalwartapi.SpamRule, bool, error)
	LookupKeys(ctx context.Context, namespace string) ([]stalwartapi.LookupKey, error)
	CreateLookupKeys(ctx context.Context, namespace string, keys []string) error
	DeleteLookupKeys(ctx context.Context, ids []string) error
	ReloadLookupStores(ctx context.Context) error
}

// newStalwartKeyClient is a var so tests can see what the client is built
// with.
var newStalwartKeyClient = stalwartapi.NewKey

// stalwartClient reads the key file on every call so a rotated key takes
// effect without a restart. var so tests can replace the client.
var stalwartClient = func(cfg *config.Config) (stalwartAPI, error) {
	key, err := stalwartapi.ReadKeyFile(cfg.Stalwart.APIKeyFile)
	if err != nil {
		return nil, err
	}
	return newStalwartKeyClient(cfg.Stalwart.APIURL, key, stalwartapi.CheckPeer), nil
}

// stalwartKeyPresent reports whether the key file exists, without reading
// it. A symlink counts so that ReadKeyFile reports why it is refused.
func stalwartKeyPresent(cfg *config.Config) bool {
	_, err := os.Lstat(cfg.Stalwart.APIKeyFile)
	return err == nil
}

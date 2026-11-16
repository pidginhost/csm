package stalwartapi

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// BlockedIP is one of Stalwart's own IP bans.
type BlockedIP struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// BlockedIPs lists Stalwart's bans on exactly address.
func (c *Client) BlockedIPs(ctx context.Context, address string) ([]BlockedIP, error) {
	ids, err := c.query(ctx, "x:BlockedIp/query", map[string]any{"address": address})
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	var list []BlockedIP
	if err := c.get(ctx, "x:BlockedIp/get", ids, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// DeleteBlockedIPs lifts the bans with these ids, then has Stalwart reload
// its ban list so the change takes effect. A failed reload is an error.
// Once the destroy is answered, Stalwart no longer lists the bans but
// enforces them until a reload, and a retry finds no ids left to delete. So
// the reload runs even after a partial destroy, is not cancelled with ctx,
// and is tried a second time when it fails.
func (c *Client) DeleteBlockedIPs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := c.set(ctx, "x:BlockedIp/set", map[string]any{"destroy": ids})
	var me *MethodError
	if err != nil && !errors.As(err, &me) && !errors.Is(err, errNotAcknowledged) {
		return err
	}
	var reloadErr error
	for range 2 {
		reloadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, reloadErr = c.set(reloadCtx, "x:Action/set", map[string]any{
			"create": map[string]any{"r": map[string]any{"@type": "ReloadBlockedIps"}},
		})
		cancel()
		if reloadErr == nil {
			return err
		}
	}
	return errors.Join(err, fmt.Errorf("reloading Stalwart's ban list: %w", reloadErr))
}

package stalwartapi

import (
	"context"
	"errors"
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
// When Stalwart answers that only some ids were destroyed, the reload still
// runs: the others are gone from the store but enforced until a reload, and a
// retry finds no ids left to delete.
func (c *Client) DeleteBlockedIPs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := c.set(ctx, "x:BlockedIp/set", map[string]any{"destroy": ids})
	var me *MethodError
	if err != nil && !errors.As(err, &me) && !errors.Is(err, errNotAcknowledged) {
		return err
	}
	_, reloadErr := c.set(ctx, "x:Action/set", map[string]any{
		"create": map[string]any{"r": map[string]any{"@type": "ReloadBlockedIps"}},
	})
	return errors.Join(err, reloadErr)
}

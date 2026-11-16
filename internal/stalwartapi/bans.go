package stalwartapi

import "context"

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
func (c *Client) DeleteBlockedIPs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := c.set(ctx, "x:BlockedIp/set", map[string]any{"destroy": ids}); err != nil {
		return err
	}
	_, err := c.set(ctx, "x:Action/set", map[string]any{
		"create": map[string]any{"r": map[string]any{"@type": "ReloadBlockedIps"}},
	})
	return err
}

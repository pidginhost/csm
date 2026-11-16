package stalwartapi

import (
	"context"
	"encoding/json"
	"fmt"
)

// APIKey is one API key of an account. Its secret is never readable.
type APIKey struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// APIKeys lists the API keys of the account accountID.
func (c *Client) APIKeys(ctx context.Context, accountID string) ([]APIKey, error) {
	var list []APIKey
	if err := c.getFor(ctx, accountID, "x:ApiKey/get", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// CreateAPIKey creates an API key for the account accountID that works only
// from allowedIPs. Stalwart returns the secret once, here.
func (c *Client) CreateAPIKey(ctx context.Context, accountID, description string, allowedIPs []string) (id, secret string, err error) {
	const method = "x:ApiKey/set"
	out, err := c.set(ctx, method, map[string]any{
		"accountId": accountID,
		"create": map[string]any{"k": map[string]any{
			"description": description,
			"allowedIps":  trueSet(allowedIPs...),
		}},
	})
	if err != nil {
		return "", "", err
	}
	var res struct {
		Created map[string]struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"created"`
	}
	// The response holds the secret, so no part of it goes into the error.
	if json.Unmarshal(out, &res) != nil || res.Created["k"].ID == "" || res.Created["k"].Secret == "" {
		return "", "", fmt.Errorf("stalwart %s: unexpected response", method)
	}
	return res.Created["k"].ID, res.Created["k"].Secret, nil
}

// DeleteAPIKeys destroys the account's API keys with these ids.
func (c *Client) DeleteAPIKeys(ctx context.Context, accountID string, ids []string) error {
	_, err := c.set(ctx, "x:ApiKey/set", map[string]any{"accountId": accountID, "destroy": ids})
	return err
}

package stalwartapi

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// Role is a Stalwart role: the permissions it enables and the roles it
// includes, both sorted.
type Role struct {
	ID, Description string
	Enabled         []string
	RoleIDs         []string
}

// RoleByDescription finds the role whose description is exactly description.
func (c *Client) RoleByDescription(ctx context.Context, description string) (Role, bool, error) {
	ids, err := c.query(ctx, "x:Role/query", map[string]any{"description": description})
	if err != nil || len(ids) == 0 {
		return Role{}, false, err
	}
	var list []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Enabled     map[string]bool `json:"enabledPermissions"`
		RoleIDs     map[string]bool `json:"roleIds"`
	}
	if err := c.get(ctx, "x:Role/get", ids, &list); err != nil {
		return Role{}, false, err
	}
	// The query filter is not documented as exact, so the match is checked here.
	for _, r := range list {
		if r.Description == description {
			return Role{ID: r.ID, Description: r.Description, Enabled: setKeys(r.Enabled), RoleIDs: setKeys(r.RoleIDs)}, true, nil
		}
	}
	return Role{}, false, nil
}

// SaveRole creates r when it has no id, and otherwise replaces its enabled
// permissions and included roles with exactly those of r. It returns the id.
func (c *Client) SaveRole(ctx context.Context, r Role) (string, error) {
	if r.ID != "" {
		_, err := c.set(ctx, "x:Role/set", map[string]any{"update": map[string]any{r.ID: map[string]any{
			"enabledPermissions": trueSet(r.Enabled...),
			"roleIds":            trueSet(r.RoleIDs...),
		}}})
		if err != nil {
			return "", err
		}
		return r.ID, nil
	}
	return c.create(ctx, "x:Role/set", map[string]any{
		"description":        r.Description,
		"enabledPermissions": trueSet(r.Enabled...),
		"roleIds":            trueSet(r.RoleIDs...),
	})
}

// Domain is one of Stalwart's mail domains.
type Domain struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Domains lists every mail domain with its aliases.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	var raw []struct {
		ID      string          `json:"id"`
		Name    string          `json:"name"`
		Aliases map[string]bool `json:"aliases"`
	}
	if err := c.get(ctx, "x:Domain/get", nil, &raw); err != nil {
		return nil, err
	}
	list := make([]Domain, 0, len(raw))
	for _, r := range raw {
		d := Domain{ID: r.ID, Name: r.Name}
		for alias, on := range r.Aliases {
			if on {
				d.Aliases = append(d.Aliases, alias)
			}
		}
		slices.Sort(d.Aliases)
		list = append(list, d)
	}
	return list, nil
}

// CreateAccount creates a user account with no password that holds only the
// role roleID, and returns its id. It can sign in only with an API key.
func (c *Client) CreateAccount(ctx context.Context, name, domainID, roleID string) (string, error) {
	return c.create(ctx, "x:Account/set", map[string]any{
		"@type":    "User",
		"name":     name,
		"domainId": domainID,
		"roles":    customRoles(roleID),
	})
}

// AccountRoleIDs lists the custom roles the account holds, sorted. A built-in
// role is none. An unknown account is an error.
func (c *Client) AccountRoleIDs(ctx context.Context, id string) ([]string, error) {
	const method = "x:Account/get"
	var list []struct {
		ID    string `json:"id"`
		Roles struct {
			RoleIDs map[string]bool `json:"roleIds"`
		} `json:"roles"`
	}
	if err := c.get(ctx, method, []string{id}, &list); err != nil {
		return nil, err
	}
	for _, a := range list {
		if a.ID == id {
			return setKeys(a.Roles.RoleIDs), nil
		}
	}
	return nil, fmt.Errorf("stalwart %s: account not found", method)
}

// AccountCredentialTypes lists the kinds of the account's credentials, such
// as Password, AppPassword or ApiKey, sorted. The credentials carry secrets,
// so only their kinds are decoded. An unknown account is an error.
func (c *Client) AccountCredentialTypes(ctx context.Context, id string) ([]string, error) {
	const method = "x:Account/get"
	out, err := c.call(ctx, method, map[string]any{"ids": []string{id}, "properties": []string{"id", "credentials"}})
	if err != nil {
		return nil, err
	}
	var res struct {
		List []struct {
			ID          string `json:"id"`
			Credentials map[string]struct {
				Type string `json:"@type"`
			} `json:"credentials"`
		} `json:"list"`
	}
	// A decode error can quote the response, so it is not passed on.
	if json.Unmarshal(out, &res) != nil {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	for _, a := range res.List {
		if a.ID != id {
			continue
		}
		types := make([]string, 0, len(a.Credentials))
		for _, cred := range a.Credentials {
			types = append(types, cred.Type)
		}
		slices.Sort(types)
		return types, nil
	}
	return nil, fmt.Errorf("stalwart %s: account not found", method)
}

// SetAccountRole makes roleID the account's only role.
func (c *Client) SetAccountRole(ctx context.Context, id, roleID string) error {
	_, err := c.set(ctx, "x:Account/set", map[string]any{"update": map[string]any{id: map[string]any{"roles": customRoles(roleID)}}})
	return err
}

func customRoles(roleID string) map[string]any {
	return map[string]any{"@type": "Custom", "roleIds": trueSet(roleID)}
}

// create sends one /set create and returns the new object's id.
func (c *Client) create(ctx context.Context, method string, object map[string]any) (string, error) {
	out, err := c.set(ctx, method, map[string]any{"create": map[string]any{"c": object}})
	if err != nil {
		return "", err
	}
	var res struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
	}
	if err := json.Unmarshal(out, &res); err != nil || res.Created["c"].ID == "" {
		return "", fmt.Errorf("stalwart %s: unexpected response", method)
	}
	return res.Created["c"].ID, nil
}

// trueSet builds the JMAP set-as-map of keys: each key mapped to true.
func trueSet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

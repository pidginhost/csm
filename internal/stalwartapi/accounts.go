package stalwartapi

import (
	"context"
	"strings"
)

// Account is one Stalwart user account.
type Account struct {
	ID, Name, Email string
	// Admin is the built-in admin role. Custom roles are not resolved.
	Admin bool
	// SignInDisabled means the account's own permissions deny sign-in.
	SignInDisabled bool
	// Inherit means the account has no permission list of its own.
	Inherit bool
}

// AccountsNamed lists the accounts whose local part is exactly name, in
// every domain.
func (c *Client) AccountsNamed(ctx context.Context, name string) ([]Account, error) {
	ids, err := c.query(ctx, "x:Account/query", map[string]any{"name": name})
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	return c.accounts(ctx, ids)
}

// AccountByAddress finds the account whose address is address. An address
// without a local part is not found. Case is ignored for ASCII letters only:
// a Unicode fold could map a crafted name onto another account.
func (c *Client) AccountByAddress(ctx context.Context, address string) (Account, bool, error) {
	address = asciiLower(address)
	local, _, ok := strings.Cut(address, "@")
	if !ok || local == "" {
		return Account{}, false, nil
	}
	list, err := c.AccountsNamed(ctx, local)
	if err != nil {
		return Account{}, false, err
	}
	for _, a := range list {
		if asciiLower(a.Email) == address {
			return a, true, nil
		}
	}
	return Account{}, false, nil
}

// Account reads one account. An unknown id is not found, not an error.
func (c *Client) Account(ctx context.Context, id string) (Account, bool, error) {
	list, err := c.accounts(ctx, []string{id})
	if err != nil {
		return Account{}, false, err
	}
	for _, a := range list {
		if a.ID == id {
			return a, true, nil
		}
	}
	return Account{}, false, nil
}

// DisableSignIn denies the account sign-in. An account that inherits its
// permissions has no list to patch, so it gets a list holding only the denial.
func (c *Client) DisableSignIn(ctx context.Context, a Account) error {
	patch := map[string]any{"permissions/disabledPermissions/authenticate": true}
	if a.Inherit {
		patch = map[string]any{"permissions": map[string]any{
			"@type":               "Merge",
			"disabledPermissions": map[string]any{"authenticate": true},
		}}
	}
	_, err := c.set(ctx, "x:Account/set", map[string]any{"update": map[string]any{a.ID: patch}})
	return err
}

// EnableSignIn removes the sign-in denial from the account's permissions and
// leaves the rest of the list alone. A missing account, or one that inherits
// its permissions, has no denial to remove.
func (c *Client) EnableSignIn(ctx context.Context, id string) error {
	a, found, err := c.Account(ctx, id)
	if err != nil || !found || a.Inherit {
		return err
	}
	_, err = c.set(ctx, "x:Account/set", map[string]any{"update": map[string]any{
		id: map[string]any{"permissions/disabledPermissions/authenticate": nil},
	}})
	return err
}

func (c *Client) accounts(ctx context.Context, ids []string) ([]Account, error) {
	var raw []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Email       string `json:"emailAddress"`
		Permissions struct {
			Type     string          `json:"@type"`
			Disabled map[string]bool `json:"disabledPermissions"`
		} `json:"permissions"`
		Roles struct {
			Type string `json:"@type"`
		} `json:"roles"`
	}
	if err := c.get(ctx, "x:Account/get", ids, &raw); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(raw))
	for _, r := range raw {
		out = append(out, Account{
			ID:             r.ID,
			Name:           r.Name,
			Email:          r.Email,
			Admin:          r.Roles.Type == "Admin",
			SignInDisabled: r.Permissions.Disabled["authenticate"],
			Inherit:        r.Permissions.Type == "Inherit",
		})
	}
	return out, nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if 'A' <= ch && ch <= 'Z' {
			b[i] = ch + 'a' - 'A'
		}
	}
	return string(b)
}

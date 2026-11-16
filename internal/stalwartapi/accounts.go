package stalwartapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// AccountByAddress finds the account that signs in as address: by its own
// address, or through a mailbox alias, a domain alias, or both. An address
// without a local part is not found. Case is ignored for ASCII letters only:
// a Unicode fold could map a crafted name onto another account. The own
// address is tried first, by local part alone, so it does not depend on
// reading the whole domain list.
func (c *Client) AccountByAddress(ctx context.Context, address string) (Account, bool, error) {
	address = asciiLower(address)
	at := strings.LastIndexByte(address, '@')
	if at <= 0 {
		return Account{}, false, nil
	}
	local, domainName := address[:at], address[at+1:]
	list, err := c.AccountsNamed(ctx, local)
	if err != nil {
		return Account{}, false, err
	}
	for _, a := range list {
		if asciiLower(a.Email) == address {
			return a, true, nil
		}
	}
	domains, err := c.Domains(ctx)
	if err != nil {
		return Account{}, false, err
	}
	i := slices.IndexFunc(domains, func(d Domain) bool {
		return d.Name == domainName || slices.Contains(d.Aliases, domainName)
	})
	if i < 0 {
		return Account{}, false, nil
	}
	domain := domains[i]
	for _, a := range list {
		if asciiLower(a.Email) == local+"@"+domain.Name {
			return a, true, nil
		}
	}
	return c.accountByAlias(ctx, local, domain.ID)
}

// accountPage is the most ids one query asks for and one get carries:
// Stalwart's limit on objects in a get.
const accountPage = 500

// accountByAlias walks every account for the one with the alias local in
// domainID. Stalwart cannot query aliases. An alias that is switched off
// still matches: it can be switched back on. A server may return fewer ids
// than asked for, so only an empty page ends the walk, and a page with no
// new id stops it with an error rather than looping.
func (c *Client) accountByAlias(ctx context.Context, local, domainID string) (Account, bool, error) {
	seen := map[string]bool{}
	for pos := 0; ; {
		ids, err := c.queryArgs(ctx, "x:Account/query", map[string]any{"limit": accountPage, "position": pos})
		if err != nil || len(ids) == 0 {
			return Account{}, false, err
		}
		fresh := false
		for _, id := range ids {
			fresh = fresh || !seen[id]
			seen[id] = true
		}
		if !fresh {
			return Account{}, false, errors.New("stalwart x:Account/query: paging repeated a page")
		}
		raw, err := c.rawAccounts(ctx, ids)
		if err != nil {
			return Account{}, false, err
		}
		for _, r := range raw {
			for _, alias := range r.Aliases {
				if alias.Name == local && alias.DomainID == domainID {
					return r.account(), true, nil
				}
			}
		}
		pos += len(ids)
	}
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
// leaves the rest of the list alone. A missing account, or one whose
// sign-ins are not denied, is left without a write.
func (c *Client) EnableSignIn(ctx context.Context, id string) error {
	a, found, err := c.Account(ctx, id)
	if err != nil || !found || a.Inherit || !a.SignInDisabled {
		return err
	}
	_, err = c.set(ctx, "x:Account/set", map[string]any{"update": map[string]any{
		id: map[string]any{"permissions/disabledPermissions/authenticate": nil},
	}})
	return err
}

// rawAccount is an account as x:Account/get returns it.
type rawAccount struct {
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
	Aliases map[string]struct {
		Name     string `json:"name"`
		DomainID string `json:"domainId"`
	} `json:"aliases"`
}

func (r rawAccount) account() Account {
	return Account{
		ID:             r.ID,
		Name:           r.Name,
		Email:          r.Email,
		Admin:          r.Roles.Type == "Admin",
		SignInDisabled: r.Permissions.Disabled["authenticate"],
		Inherit:        r.Permissions.Type == "Inherit",
	}
}

// accountProperties are the fields rawAccount decodes. A whole account also
// carries its credentials, secrets included, which CSM must never read.
var accountProperties = []string{"id", "name", "emailAddress", "permissions", "roles", "aliases"}

func (c *Client) rawAccounts(ctx context.Context, ids []string) ([]rawAccount, error) {
	const method = "x:Account/get"
	out, err := c.call(ctx, method, map[string]any{"ids": ids, "properties": accountProperties})
	if err != nil {
		return nil, err
	}
	var res struct {
		List []rawAccount `json:"list"`
	}
	// A decode error can quote the response, so it is not passed on.
	if json.Unmarshal(out, &res) != nil || res.List == nil {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	return res.List, nil
}

func (c *Client) accounts(ctx context.Context, ids []string) ([]Account, error) {
	raw, err := c.rawAccounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.account())
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

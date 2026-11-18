package stalwartapi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// lookupPage is Stalwart's limit on objects in one get and one set.
const lookupPage = 500

// LookupKey is one key of a Stalwart in-memory lookup list.
type LookupKey struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Glob bool   `json:"isGlobPattern"`
}

// LookupKeys lists every key in namespace once. A server may return fewer
// ids than asked for, so only an empty page ends the walk, ids already seen
// are skipped, and a page with no new id stops it with an error rather than
// looping.
func (c *Client) LookupKeys(ctx context.Context, namespace string) ([]LookupKey, error) {
	const method = "x:MemoryLookupKey/get"
	var all []LookupKey
	seen := map[string]bool{}
	for pos := 0; ; {
		ids, err := c.queryArgs(ctx, "x:MemoryLookupKey/query", map[string]any{
			"filter": map[string]any{"namespace": namespace}, "limit": lookupPage, "position": pos,
		})
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return all, nil
		}
		var fresh []string
		for _, id := range ids {
			if !seen[id] {
				fresh = append(fresh, id)
				seen[id] = true
			}
		}
		if len(fresh) == 0 {
			return nil, errors.New("stalwart x:MemoryLookupKey/query: paging repeated a page")
		}
		for page := range slices.Chunk(fresh, lookupPage) {
			out, err := c.call(ctx, method, map[string]any{"ids": page, "properties": []string{"key", "isGlobPattern"}})
			if err != nil {
				return nil, err
			}
			var res struct {
				List []LookupKey `json:"list"`
			}
			// A decode error can quote the response, so it is not passed on.
			if json.Unmarshal(out, &res) != nil || res.List == nil {
				return nil, fmt.Errorf("stalwart %s: unexpected response", method)
			}
			all = append(all, res.List...)
		}
		pos += len(ids)
	}
}

// CreateLookupKeys adds keys to namespace. A key holding "*" is a glob.
// The keys take effect after ReloadLookupStores.
func (c *Client) CreateLookupKeys(ctx context.Context, namespace string, keys []string) error {
	for page := range slices.Chunk(keys, lookupPage) {
		create := make(map[string]any, len(page))
		for i, key := range page {
			create["k"+strconv.Itoa(i)] = map[string]any{"namespace": namespace, "key": key, "isGlobPattern": strings.Contains(key, "*")}
		}
		if _, err := c.set(ctx, "x:MemoryLookupKey/set", map[string]any{"create": create}); err != nil {
			return err
		}
	}
	return nil
}

// DeleteLookupKeys removes the keys with these ids. The change takes effect
// after ReloadLookupStores.
func (c *Client) DeleteLookupKeys(ctx context.Context, ids []string) error {
	for page := range slices.Chunk(ids, lookupPage) {
		if _, err := c.set(ctx, "x:MemoryLookupKey/set", map[string]any{"destroy": page}); err != nil {
			return err
		}
	}
	return nil
}

// ReloadLookupStores has Stalwart read its lookup lists again, which is
// when created and deleted keys take effect.
func (c *Client) ReloadLookupStores(ctx context.Context) error {
	_, err := c.set(ctx, "x:Action/set", map[string]any{
		"create": map[string]any{"r": map[string]any{"@type": "ReloadLookupStores"}},
	})
	return err
}

// SpamRule is one Stalwart spam filter rule. Arms are tried in order and the
// first match wins; Else is the result when none match.
type SpamRule struct {
	ID, Type string
	Enabled  bool
	Arms     []RuleArm
	Else     string
}

// RuleArm is one if/then pair of a rule's condition.
type RuleArm struct {
	If   string `json:"if"`
	Then string `json:"then"`
}

// SpamRule reads the rule named name. A missing rule is not found, not an
// error.
func (c *Client) SpamRule(ctx context.Context, name string) (SpamRule, bool, error) {
	const method = "x:SpamRule/get"
	ids, err := c.query(ctx, "x:SpamRule/query", map[string]any{"name": name})
	if err != nil || len(ids) == 0 {
		return SpamRule{}, false, err
	}
	var list []struct {
		ID        string `json:"id"`
		Type      string `json:"@type"`
		Enable    bool   `json:"enable"`
		Condition struct {
			Match map[string]RuleArm `json:"match"`
			Else  string             `json:"else"`
		} `json:"condition"`
	}
	if err := c.get(ctx, method, ids[:1], &list); err != nil {
		return SpamRule{}, false, err
	}
	if len(list) == 0 {
		return SpamRule{}, false, nil
	}
	raw := list[0]
	type numbered struct {
		n   uint64
		key string
	}
	var keys []numbered
	for key := range raw.Condition.Match {
		n, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return SpamRule{}, false, fmt.Errorf("stalwart %s: unexpected response", method)
		}
		keys = append(keys, numbered{n, key})
	}
	slices.SortFunc(keys, func(a, b numbered) int { return cmp.Or(cmp.Compare(a.n, b.n), strings.Compare(a.key, b.key)) })
	r := SpamRule{ID: raw.ID, Type: raw.Type, Enabled: raw.Enable, Else: raw.Condition.Else}
	for _, k := range keys {
		r.Arms = append(r.Arms, raw.Condition.Match[k.key])
	}
	return r, true, nil
}

// CreateSpamRule adds an enabled rule named name that matches r's arms, with
// Stalwart's default priority.
func (c *Client) CreateSpamRule(ctx context.Context, name string, r SpamRule) error {
	_, err := c.set(ctx, "x:SpamRule/set", map[string]any{"create": map[string]any{"r": map[string]any{
		"@type": "Any", "name": name, "enable": true, "condition": ruleCondition(r.Arms, r.Else),
	}}})
	return err
}

// SetSpamRuleCondition replaces the condition of the rule with id and leaves
// its other fields alone.
func (c *Client) SetSpamRuleCondition(ctx context.Context, id string, arms []RuleArm, elseExpr string) error {
	_, err := c.set(ctx, "x:SpamRule/set", map[string]any{"update": map[string]any{
		id: map[string]any{"condition": ruleCondition(arms, elseExpr)},
	}})
	return err
}

func ruleCondition(arms []RuleArm, elseExpr string) map[string]any {
	match := make(map[string]RuleArm, len(arms))
	for i, arm := range arms {
		match[strconv.Itoa(i)] = arm
	}
	return map[string]any{"match": match, "else": elseExpr}
}

// SpamTag is one Stalwart spam filter tag and its score.
type SpamTag struct {
	ID    string  `json:"id"`
	Type  string  `json:"@type"`
	Tag   string  `json:"tag"`
	Score float64 `json:"score"`
}

// SpamTag reads the tag named tag. A missing tag is not found, not an error.
func (c *Client) SpamTag(ctx context.Context, tag string) (SpamTag, bool, error) {
	ids, err := c.query(ctx, "x:SpamTag/query", map[string]any{"tag": tag})
	if err != nil || len(ids) == 0 {
		return SpamTag{}, false, err
	}
	var list []SpamTag
	if err := c.get(ctx, "x:SpamTag/get", ids[:1], &list); err != nil || len(list) == 0 {
		return SpamTag{}, false, err
	}
	return list[0], true, nil
}

// CreateSpamTag adds a scoring tag named tag.
func (c *Client) CreateSpamTag(ctx context.Context, tag string, score float64) error {
	_, err := c.set(ctx, "x:SpamTag/set", map[string]any{"create": map[string]any{
		"t": map[string]any{"@type": "Score", "tag": tag, "score": score},
	}})
	return err
}

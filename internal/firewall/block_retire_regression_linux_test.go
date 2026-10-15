//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

// Visibility after rename is not durability. A retry must finish a state
// write before reporting success, even when it can already see no row.
func TestBlockActionCleanupRetriesUnconfirmedWrite(t *testing.T) {
	for _, operation := range []string{"remove", "retire"} {
		for _, renamed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/renamed=%t", operation, renamed), func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.104", ActionID: "act_own", Unverified: true}}})
				prev := writeFirewallStateJSON
				t.Cleanup(func() { writeFirewallStateJSON = prev })
				cause := errors.New("fixture unconfirmed state write")
				writes := 0
				writeFirewallStateJSON = func(path string, mode os.FileMode, value any) error {
					writes++
					if renamed {
						if err := prev(path, mode, value); err != nil {
							return err
						}
					}
					return cause
				}
				for range 2 {
					if operation == "remove" {
						if removed, err := f.e.RemoveBlockActionRows([]string{"act_own"}); !errors.Is(err, cause) || removed != 0 {
							t.Fatalf("unconfirmed removal = %d, %v", removed, err)
						}
					} else if clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: "203.0.113.104"}}); !errors.Is(err, cause) || clear != nil {
						t.Fatalf("unconfirmed retirement = %v, %v", clear, err)
					}
				}
				writeFirewallStateJSON = func(path string, mode os.FileMode, value any) error {
					writes++
					return prev(path, mode, value)
				}
				if operation == "remove" {
					want := 1
					if renamed {
						want = 0
					}
					if removed, err := f.e.RemoveBlockActionRows([]string{"act_own"}); err != nil || removed != want {
						t.Fatalf("retry = %d, %v; want %d", removed, err, want)
					}
				} else if clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: "203.0.113.104"}}); err != nil || len(clear) != 1 || !clear[0] {
					t.Fatalf("retry = %v, %v", clear, err)
				}
				if rows := readRawFirewallState(t, f.e).Blocked; len(rows) != 0 || writes != 3 {
					t.Fatalf("retry left rows %+v after %d writes; want none after 3 writes", rows, writes)
				}
			})
		}
	}
}

// Recovery must keep the identities of both rows until the named attempt
// is clear, even when the normal address view prefers its unverified row.
func TestRetireBlockActionsPreservesSharedRows(t *testing.T) {
	for _, forms := range []struct{ own, other, target string }{
		{"203.0.113.100", "203.0.113.100", "203.0.113.100"},
		{"::ffff:203.0.113.100", "203.0.113.100", "203.0.113.100"},
		{"2001:db8::100", "2001:DB8::100", "2001:db8::100"},
		{"2001:db8::100", "2001:db8::100%fixture", "2001:db8::100"},
	} {
		for _, kernel := range []string{"absent", "matching", "timeout", "permanent"} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%s/reverse=%t", forms.own, forms.other, kernel, reverse), func(t *testing.T) {
					f := newBatchFixture(t, FirewallState{})
					own := BlockedEntry{IP: forms.own, ActionID: "act_own", Unverified: true, ExpiresAt: f.at.Add(-time.Hour)}
					other := BlockedEntry{IP: forms.other, ActionID: "act_other", ExpiresAt: f.at.Add(time.Hour)}
					rows := []BlockedEntry{own, other}
					if reverse {
						rows[0], rows[1] = rows[1], rows[0]
					}
					writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
					switch kernel {
					case "matching":
						f.live[forms.target] = time.Hour
					case "timeout":
						f.live[forms.target] = 2 * time.Hour
					case "permanent":
						f.live[forms.target] = 0
					}
					writes := f.countWrites(t)
					clear, err := f.e.RetireBlockActions([]BlockAction{{Action: own.ActionID, IP: forms.target}})
					wantClear := kernel == "absent" || kernel == "matching"
					if err != nil || len(clear) != 1 || clear[0] != wantClear {
						t.Fatalf("retirement = %v, %v; want clear=%t", clear, err, wantClear)
					}
					wantRows, wantWrites := rows, 0
					if wantClear {
						wantRows, wantWrites = []BlockedEntry{other}, 1
					}
					if got := readRawFirewallState(t, f.e).Blocked; !reflect.DeepEqual(got, wantRows) || *writes != wantWrites {
						t.Fatalf("remaining rows = %+v with %d writes; want %+v with %d writes", got, *writes, wantRows, wantWrites)
					}
				})
			}
		}
	}
}

// Cleaning one action must not merge unrelated rows that share an address.
func TestBlockActionCleanupPreservesUnrelatedRows(t *testing.T) {
	for _, operation := range []string{"remove", "retire"} {
		t.Run(operation, func(t *testing.T) {
			kept := []BlockedEntry{
				{IP: "203.0.113.101", ActionID: "act_first", Unverified: true},
				{IP: "::ffff:203.0.113.101", ActionID: "act_second", Unverified: true},
			}
			f := newBatchFixture(t, FirewallState{Blocked: append([]BlockedEntry{{IP: "203.0.113.102", ActionID: "act_own", Unverified: true}}, kept...)})
			if operation == "remove" {
				if removed, err := f.e.RemoveBlockActionRows([]string{"act_own"}); err != nil || removed != 1 {
					t.Fatalf("remove = %d, %v", removed, err)
				}
			} else if clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: "203.0.113.102"}}); err != nil || len(clear) != 1 || !clear[0] {
				t.Fatalf("retire = %v, %v", clear, err)
			}
			if got := readRawFirewallState(t, f.e).Blocked; !reflect.DeepEqual(got, kept) {
				t.Fatalf("remaining rows = %+v; want %+v", got, kept)
			}
		})
	}
}

// A family omitted from the kernel dump cannot prove an absent element.
func TestRetireBlockActionsRequiresIPv6Snapshot(t *testing.T) {
	for _, unavailable := range []string{"disabled", "missing"} {
		t.Run(unavailable, func(t *testing.T) {
			state := FirewallState{Blocked: []BlockedEntry{{IP: "2001:db8::103", ActionID: "act_own", Unverified: true}}}
			f := newBatchFixture(t, state)
			f.live["2001:db8::103"] = time.Hour
			if unavailable == "disabled" {
				f.e.cfg.IPv6 = false
			} else {
				f.e.setBlocked6 = nil
			}
			writes := f.countWrites(t)
			clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: "2001:db8::103"}})
			if err != nil || len(clear) != 1 || clear[0] {
				t.Fatalf("missing snapshot authorized retirement: %v, %v", clear, err)
			}
			if got := readRawFirewallState(t, f.e); !reflect.DeepEqual(got, state) || *writes != 0 {
				t.Fatalf("missing snapshot changed rows: %+v, writes %d", got, *writes)
			}
		})
	}
}

// An address family the snapshot cannot read holds only its own members:
// the rest of the batch still gets its answer, so one such attempt cannot
// stall every retirement behind it.
func TestRetireBlockActionsUnreadableFamilyHoldsOnlyItsMembers(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.105", ActionID: "act_four", Unverified: true},
		{IP: "2001:db8::105", ActionID: "act_six", Unverified: true},
	}})
	f.e.cfg.IPv6 = false
	clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_six", IP: "2001:db8::105"}, {Action: "act_four", IP: "203.0.113.105"}})
	if err != nil || len(clear) != 2 || clear[0] || !clear[1] {
		t.Fatalf("retirement = %v, %v; want the IPv6 attempt held and the IPv4 one clear", clear, err)
	}
	if got := readRawFirewallState(t, f.e).Blocked; len(got) != 1 || got[0].ActionID != "act_six" {
		t.Fatalf("remaining rows = %+v; want only the held IPv6 row", got)
	}
}

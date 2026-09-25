//go:build linux

package firewall

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/actionlog"
)

func TestProtectedAddressTimedBlockRefusal(t *testing.T) {
	for _, ip := range protectedAddressCases {
		for _, priorKind := range []string{"absent", "permanent", "longer", "shorter"} {
			for _, operation := range []string{"preserve-lifetime", "capture-undo"} {
				t.Run(ip+"/"+priorKind+"/"+operation, func(t *testing.T) {
					sink := withActionSink(t)
					conn, captured := nftConnCapturingRules(t)
					e := newProtectedAddressEngine(t, conn)
					e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) {
						t.Error("protected target reached kernel lifetime lookup")
						return nil, errors.New("kernel unavailable")
					}
					prior := FirewallState{}
					if priorKind != "absent" {
						entry := BlockedEntry{IP: net.ParseIP(ip).String(), Reason: "legacy block", BlockedAt: time.Now()}
						switch priorKind {
						case "longer":
							entry.ExpiresAt = time.Now().Add(2 * time.Hour)
						case "shorter":
							entry.ExpiresAt = time.Now().Add(time.Minute)
						}
						prior.Blocked = []BlockedEntry{entry}
					}
					writeRawFirewallState(t, e, prior)
					prior = readRawFirewallState(t, e)
					var err error
					if operation == "preserve-lifetime" {
						err = e.BlockIPForcePreserveLifetime(ip, "timed block", time.Hour)
					} else {
						var before, after *BlockedEntry
						before, after, err = e.BlockIPForUndo(ip, "timed block", time.Hour)
						if before != nil || after != nil {
							t.Error("refused block returned undo snapshots")
						}
					}
					if !errors.Is(err, ErrIPProtected) {
						t.Errorf("error = %v, want ErrIPProtected", err)
					}
					if len(sink.records) != 1 || sink.records[0].Result != actionlog.Refused {
						t.Errorf("records = %+v, want one refusal", sink.records)
					}
					if len(*captured) != 0 || !reflect.DeepEqual(readRawFirewallState(t, e), prior) {
						t.Fatal("refused block changed kernel or persisted state")
					}
				})
			}
		}
	}
}

func TestTimedBlockLifetimeRefusalPrecedesCapacity(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		conn, captured := nftConnCapturingRules(t)
		e := newProtectedAddressEngine(t, conn)
		e.cfg.DenyTempIPLimit = 1
		e.liveBlockCounts = func() (int, int, error) { return 0, 1, nil }
		entry := BlockedEntry{IP: "192.0.2.10", ExpiresAt: time.Now().Add(2 * time.Hour)}
		want := ErrLongerBlock
		if permanent {
			entry.ExpiresAt = time.Time{}
			want = ErrPermanentBlock
		}
		writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{entry}})
		prior := readRawFirewallState(t, e)
		if err := e.BlockIPForcePreserveLifetime(entry.IP, "timed block", time.Hour); !errors.Is(err, want) {
			t.Errorf("permanent=%t: error=%v, want %v", permanent, err, want)
		}
		if len(*captured) != 0 || !reflect.DeepEqual(readRawFirewallState(t, e), prior) {
			t.Fatal("lifetime refusal changed kernel or persisted state")
		}
	}
}

func TestSubnetDryRunValidatesTarget(t *testing.T) {
	for _, tc := range []struct {
		cidr   string
		want   error
		result actionlog.Result
	}{
		{"224.0.1.0/24", ErrIPProtected, actionlog.Refused},
		{"::ffff:239.0.0.0/104", ErrIPProtected, actionlog.Refused},
		{"ff0e::/16", ErrIPProtected, actionlog.Refused},
		{"255.255.255.255/32", ErrIPProtected, actionlog.Refused},
		{"::ffff:255.255.255.255/128", ErrIPProtected, actionlog.Refused},
		{"192.0.2.0/24", ErrActionDryRun, actionlog.DryRun},
		{"2001:db8::/64", ErrActionDryRun, actionlog.DryRun},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			sink := withActionSink(t)
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			e.SetDryRunEnabledFunc(func() bool { return true })
			writeRawFirewallState(t, e, FirewallState{})
			prior := readRawFirewallState(t, e)
			err := e.BlockSubnetRequest(ActionRequest{
				ID: "subnet-dry-run", Target: tc.cidr, Reason: "automatic subnet block",
				TTL: time.Hour, Automatic: true, FindingID: "subnet-finding",
			}, nil)
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
			if len(sink.records) != 1 || sink.records[0].Result != tc.result || sink.records[0].FindingID != "subnet-finding" {
				t.Errorf("records = %+v, want %s with finding identity", sink.records, tc.result)
			}
			if len(*captured) != 0 || !reflect.DeepEqual(readRawFirewallState(t, e), prior) {
				t.Fatal("dry-run changed kernel or persisted state")
			}
		})
	}
}

type protectedRequestStore struct{ replayLifecycleStore }

func (protectedRequestStore) ReadFirewallAction(string) (FirewallAction, error) {
	return FirewallAction{}, ErrActionMissing
}

func TestProtectedLifecycleRequestsRefused(t *testing.T) {
	for _, ip := range protectedAddressCases {
		for _, operation := range []string{"automatic", "manual", "preserve-lifetime", "promote", "subnet-dry-run"} {
			t.Run(ip+"/"+operation, func(t *testing.T) {
				sink := withActionSink(t)
				conn, captured := nftConnCapturingRules(t)
				e := newProtectedAddressEngine(t, conn)
				prior := FirewallState{Blocked: []BlockedEntry{{
					IP: net.ParseIP(ip).String(), Reason: "legacy block", ExpiresAt: time.Now().Add(2 * time.Hour),
				}}}
				store := protectedRequestStore{replayLifecycleStore{current: copyFirewallState(prior)}}
				if err := e.AttachLifecycle(&Lifecycle{Store: store}); err != nil {
					t.Fatal(err)
				}
				e.SetDryRunEnabledFunc(func() bool { return true })
				var err error
				switch operation {
				case "preserve-lifetime":
					err = e.BlockIPForcePreserveLifetime(ip, "timed block", time.Hour)
				case "promote":
					err = e.PromoteToPermanentBlock(ip, "permanent block")
				case "subnet-dry-run":
					cidr := ip + "/128"
					if ip == net.ParseIP(ip).To4().String() {
						cidr = ip + "/32"
					}
					err = e.BlockSubnetRequest(ActionRequest{ID: "protected-subnet", Target: cidr, Automatic: true}, nil)
				default:
					var outcome BlockOutcome
					outcome, err = e.BlockIPRequest(ActionRequest{
						ID: "protected-block", Target: ip, Automatic: operation == "automatic", TTL: time.Hour,
					}, nil)
					if outcome != BlockOutcomeNoop {
						t.Errorf("outcome = %s, want no-op", outcome)
					}
				}
				if !errors.Is(err, ErrIPProtected) {
					t.Errorf("error = %v, want ErrIPProtected", err)
				}
				if len(sink.records) != 1 || sink.records[0].Result != actionlog.Refused {
					t.Errorf("records = %+v, want one refusal", sink.records)
				}
				if len(*captured) != 0 || !reflect.DeepEqual(e.loadStateFile(), prior) {
					t.Fatal("refused request changed kernel or committed state")
				}
			})
		}
	}
}

func TestManualBlockRequestAudit(t *testing.T) {
	for _, mode := range []string{"new", "replay"} {
		t.Run(mode, func(t *testing.T) {
			replay := mode == "replay"
			sink := withActionSink(t)
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			req := normalizeActionRequest(ActionRequest{
				ID: "manual-block", Operation: "block", Target: "192.0.2.10", Reason: "via CLI", FindingID: "block-finding",
			})
			if replay {
				store := replayLifecycleStore{action: FirewallAction{Request: req, Phase: "verified"}}
				if err := e.AttachLifecycle(&Lifecycle{Store: store}); err != nil {
					t.Fatal(err)
				}
			}
			outcome, err := e.BlockIPRequest(req, nil)
			if err != nil {
				t.Fatal(err)
			}
			if replay {
				if outcome != BlockOutcomeNoop || len(sink.records) != 0 || len(*captured) != 0 {
					t.Fatalf("replay repeated an effect: outcome=%s records=%+v messages=%d", outcome, sink.records, len(*captured))
				}
				return
			}
			if outcome != BlockOutcomeLive || len(sink.records) != 1 {
				t.Fatalf("manual outcome=%s records=%+v", outcome, sink.records)
			}
			rec := sink.records[0]
			if rec.Result != actionlog.Applied || rec.Target != req.Target || rec.FindingID != req.FindingID || rec.Op != "operate.manual_firewall" {
				t.Fatalf("incorrect manual audit record: %+v", rec)
			}
		})
	}
}

func TestMulticastLegacySubnetReloadAndRemoval(t *testing.T) {
	for _, tc := range []struct{ cidr, start, end string }{
		{"224.0.1.0/24", "224.0.1.0", "224.0.2.0"},
		{"ff0e::/16", "ff0e::", "ff0f::"},
		{"ff00::/8", "ff00::", ""},
		{"255.255.255.255/32", "255.255.255.255", ""},
		{"::ffff:255.255.255.255/128", "255.255.255.255", ""},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			conn, captured := nftConnCapturingRules(t)
			e := newProtectedAddressEngine(t, conn)
			e.listTables = func() ([]*nftables.Table, error) { return nil, nil }
			e.readRuleset = func() (string, error) { return "table inet csm {}", nil }
			state := FirewallState{BlockedNet: []SubnetEntry{{CIDR: mustCIDR(t, tc.cidr).String(), Reason: "legacy subnet"}}}
			writeRawFirewallState(t, e, state)
			setName := "blocked_nets"
			if net.ParseIP(tc.start).To4() == nil {
				setName += "6"
			}
			wantCount := 1
			if tc.end != "" {
				wantCount++
			}
			// Both reload planners must preserve old entries so they stay
			// visible and removable, including open-ended intervals.
			elems := desiredActionSets(state, true, time.Now())[setName]
			if len(elems) != wantCount || elems[0].End || !net.IP(elems[0].Key).Equal(net.ParseIP(tc.start)) {
				t.Fatalf("restored interval = %+v", elems)
			}
			if tc.end != "" && (!elems[1].End || !net.IP(elems[1].Key).Equal(net.ParseIP(tc.end))) {
				t.Fatalf("restored interval end = %+v, want %s", elems[1], tc.end)
			}
			if err := e.Apply(); err != nil {
				t.Fatal(err)
			}
			if got := len(newSetElemTimeouts(t, *captured, setName)); got != wantCount || !e.IsSubnetBlocked(tc.cidr) {
				t.Fatalf("legacy subnet restore: elements=%d want=%d", got, wantCount)
			}
			if err := e.UnblockSubnet(tc.cidr); err != nil {
				t.Fatal(err)
			}
			if e.IsSubnetBlocked(tc.cidr) || len(readRawFirewallState(t, e).BlockedNet) != 0 {
				t.Fatal("legacy subnet survived removal")
			}
			*captured = nil
			if err := e.Apply(); err != nil {
				t.Fatal(err)
			}
			if len(newSetElemTimeouts(t, *captured, setName)) != 0 {
				t.Fatal("reload resurrected removed subnet")
			}
		})
	}
}

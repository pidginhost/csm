package admission

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func FuzzCanonicalTargets(f *testing.F) {
	for _, s := range []string{
		"192.0.2.1", "::ffff:192.0.2.1", "198.51.100.7/24", "2001:db8::/32",
		"fe80::1%eth0", "ip:192.0.2.1", "svc:192.0.2.1/tcp/22",
		"::fffe:0:0/95", "::ff00:0:0/88", "net:::fffe:0:0/95",
	} {
		f.Add(s)
	}
	mapped := netip.MustParsePrefix("::ffff:0:0/96")
	f.Fuzz(func(t *testing.T, raw string) {
		for _, parse := range []func(string, Caps) (Target, error){CanonicalAddress, CanonicalPrefix, ParseTargetKey} {
			got, err := parse(raw, v6)
			if err != nil {
				if _, ok := ReasonOf(err); !ok {
					t.Fatalf("refusal without a reason: %v", err)
				}
				continue
			}
			again, err := ParseTargetKey(got.Key(), v6)
			if err != nil || again != got {
				t.Fatalf("key %q does not round-trip: %v", got.Key(), err)
			}
			if got.Prefix().Overlaps(mapped) {
				t.Fatalf("accepted %q overlaps IPv4-mapped IPv6", got.Key())
			}
			for _, p := range protectedPrefixes {
				if p.Overlaps(got.Prefix()) {
					t.Fatalf("accepted %q overlaps protected %s", got.Key(), p)
				}
			}
		}
	})
}

func FuzzUnmarshalEvidence(f *testing.F) {
	reg, _ := NewRegistry(testLookup)
	p, _ := reg.Register(ProducerSpec{ID: "sshd_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}})
	tg, _ := CanonicalAddress("192.0.2.1", Caps{})
	e, _ := p.Mint(EvidenceInput{Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: SeverityHigh, Observation: ObservationRef{"s", "c", 1}, ObservedAt: t0, Parser: ParserRef{"sshd", 1}, Target: tg})
	seed, _ := e.MarshalBinary()
	f.Add(seed)
	f.Add([]byte("E\x01{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		check := func(data []byte) {
			got, err := UnmarshalEvidence(data)
			if err != nil {
				if _, ok := ReasonOf(err); !ok {
					t.Fatalf("refusal without a reason: %v", err)
				}
				return
			}
			again, err := got.MarshalBinary()
			if err != nil || !bytes.Equal(again, data) {
				t.Fatal("accepted a non-canonical record")
			}
			if err := validateRecord(got.rec); err != nil {
				t.Fatalf("accepted an invalid record: %v", err)
			}
			if got.Target().IsZero() {
				t.Fatal("accepted a record without a target")
			}
		}
		check(data)
		// Mutations must also reach the decoder past the corruption check.
		if len(data) >= 12 && len(data) <= MaxEvidenceBytes {
			check(resealFuzzRecord(data))
		}
	})
}

func FuzzGenerations(f *testing.F) {
	g := NewGenerations()
	if _, err := g.Observe([]string{"alice"}); err != nil {
		f.Fatal(err)
	}
	seed, err := g.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(resealFuzzRecord(append([]byte(`{"v":1,"next":2,"live":null}`), make([]byte, 8)...)))
	f.Fuzz(func(t *testing.T, data []byte) {
		check := func(data []byte) {
			var restored Generations
			if err := restored.UnmarshalBinary(seed); err != nil {
				t.Fatal(err)
			}
			err := restored.UnmarshalBinary(data)
			after, encodeErr := restored.MarshalBinary()
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if err != nil {
				if !bytes.Equal(after, seed) {
					t.Fatal("refused restore changed the tracker")
				}
			} else if !bytes.Equal(after, data) {
				t.Fatal("accepted a non-canonical tracker")
			}
		}
		check(data)
		if len(data) >= 8 {
			check(resealFuzzRecord(data))
		}
	})
}

// Both persisted formats end with an eight-byte checksum.
func resealFuzzRecord(data []byte) []byte {
	out := append([]byte(nil), data...)
	head := out[:len(out)-8]
	sum := sha256.Sum256(head)
	copy(out[len(head):], sum[:8])
	return out
}

// Every ledger record decoder either refuses its input or accepts bytes that
// re-encode exactly, and none panics on damaged storage.
func FuzzLedgerRecords(f *testing.F) {
	target, _ := CanonicalAddress("192.0.2.10", Caps{})
	episode, _ := ParseEpisodeID("00000000000000000000000000000001")
	cand := Candidate{
		Key:   CandidateKey{Kind: KindBlockIP, Target: target, Episode: episode, Generation: 1},
		Scope: Scope{Effect: EffectAddress}, Entry: EntryScan, Check: "ssh_brute", FindingID: "0123456789abcdef",
		Roots: []EvidenceID{"ev_00000000000000000000000000000001"}, FirstQueued: t0, AgeOut: t0.Add(time.Hour),
		State: StateQueued, Transitions: 1,
	}
	id, _ := cand.ID()
	attempt, _ := NewAttempt(id, 1)
	clock, _, _ := Clock{}.Advance(ClockReading{Wall: t0, BootID: "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b", SinceBoot: time.Hour})
	inv, _ := NewInventory(map[string]uint64{"alice": 1}, map[string]string{"alice.example": "alice"})
	links, _, _ := ReportLinks{Evidence: "ev_00000000000000000000000000000001"}.Add("0123456789abcdef")
	var counters QueueCounters
	_ = counters.Add(CountKey{Event: EventEnded, Reason: ReasonStale, Class: ClassC2, Severity: SeverityHigh})
	counterBytes, _ := counters.MarshalBinary()
	ceiling, _ := CeilingState{Fill: true}.SetLimit(2000)
	ceiling, _ = ceiling.Advance(time.Minute)
	ceiling, _ = ceiling.Charge(LaneDirect, 2)
	charge := Charge{At: t0, Action: attempt.ID, Lane: LaneDirect, Cost: 2, Elapsed: time.Minute}
	chargeKey, _ := charge.Key()
	history := HistoryEntry{General: 3000, Reserved: 400, Ended: t0, Eligible: t0.Add(HistoryRetention)}
	retireKeys, _ := history.RetireKeys(id)
	for _, rec := range []interface{ MarshalBinary() ([]byte, error) }{
		cand, AttemptRecord{Attempt: attempt, State: StateReserved, ExpiresAt: t0.Add(time.Hour), Reserved: t0, Lane: LaneGeneral}, clock, inv, links,
		QueueEntry{Partition: PartitionReserved, Tier: Tier{ClassC3, SeverityHigh}, Direct: true, NextChange: t0},
		QueueState{NextSweep: t0, Cursors: QueueCursors{General: "host/address"}}, counters,
		ScheduleState{ClassSlot: 3, Rings: [ringCount]Ring{ringC2: {Last: "host/address", Scopes: map[string]ScopeTurn{"host/address": {Severity: 1, Deficit: 2, Bytes: 4096}}}}},
		IngressState{Generation: 2, Open: true, Persisted: 5, Interrupted: 1, Checkpoint: &IngressCheckpoint{
			Generation: 2, Sequence: 3, Cursors: QueueCursors{General: "host/address"}, Counters: counterBytes,
		}},
		ceiling, charge, history, EvidenceRefs{Refs: 2}, EvidenceRefs{Loose: 7},
		StorageState{General: HistoryMeter{Credit: 5, Used: 9}, Recovery: 3, Ended: RingState{Count: 1, Last: 4}},
	} {
		data, err := rec.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, k := range retireKeys {
		f.Add(k)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		check := func(data []byte) {
			roundTrip := func(what string, rec interface{ MarshalBinary() ([]byte, error) }) {
				out, err := rec.MarshalBinary()
				if err != nil || !bytes.Equal(out, data) {
					t.Fatalf("accepted %s does not re-encode to its input: %v", what, err)
				}
			}
			if c, err := UnmarshalClock(data); err == nil {
				roundTrip("clock", c)
			}
			if c, err := UnmarshalCandidate(data); err == nil {
				roundTrip("candidate", c)
			}
			if a, err := UnmarshalAttempt(data); err == nil {
				roundTrip("attempt", a)
			}
			if inv, err := UnmarshalInventory(data); err == nil {
				roundTrip("inventory", inv)
			}
			if r, err := UnmarshalReportLinks(data); err == nil {
				roundTrip("report links", r)
			}
			if q, err := UnmarshalQueueEntry(data); err == nil {
				roundTrip("queue entry", q)
			}
			if s, err := UnmarshalQueueState(data); err == nil {
				roundTrip("queue state", s)
			}
			if q, err := UnmarshalQueueCounters(data); err == nil {
				roundTrip("queue counters", q)
			}
			if s, err := UnmarshalScheduleState(data); err == nil {
				roundTrip("schedule state", s)
			}
			if s, err := UnmarshalIngressState(data); err == nil {
				roundTrip("ingress state", s)
			}
			if s, err := UnmarshalCeilingState(data); err == nil {
				roundTrip("ceiling state", s)
			}
			if c, err := UnmarshalCharge(chargeKey, data); err == nil {
				roundTrip("charge", c)
			}
			if h, err := UnmarshalHistoryEntry(data); err == nil {
				roundTrip("history entry", h)
			}
			if r, err := UnmarshalEvidenceRefs(data); err == nil {
				roundTrip("evidence references", r)
			}
			if s, err := UnmarshalStorageState(data); err == nil {
				roundTrip("storage state", s)
			}
			if kind, at, cand, err := ParseRetireKey(data); err == nil {
				if again := fmt.Appendf(nil, "%c%019d%s", kind, at.UnixNano(), cand); !bytes.Equal(again, data) {
					t.Fatalf("accepted retirement key does not re-encode to its input: %q", data)
				}
			}
		}
		check(data)
		if len(data) >= 8 {
			check(resealFuzzRecord(data))
		}
	})
}

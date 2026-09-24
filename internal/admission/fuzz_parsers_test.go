package admission

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"testing"
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

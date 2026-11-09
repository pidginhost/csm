package admission

import "testing"

// A response may act on the address its evidence attributes; a range entry
// may act on a prefix containing it. Any other target is an attribution
// refusal (spec 5.8, 5.13).
func TestBindTarget(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	in.Target = mustAddr(t, "198.51.100.7")
	e, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		target Target
		via    Entry
	}{
		"the address":                   {mustAddr(t, "198.51.100.7"), 0},
		"the address through incidents": {mustAddr(t, "198.51.100.7"), EntryIncident},
		"a service on it":               {mustService(t, "198.51.100.7", "tcp", 22), 0},
		"a mail subnet holding it":      {mustPrefix(t, "198.51.100.0/24"), EntryMailSubnet},
		"a crawl range holding it":      {mustPrefix(t, "198.51.100.0/25"), EntryASNCrawl},
	} {
		if err := BindTarget(c.target, c.via, e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		target Target
		via    Entry
	}{
		"another address":            {mustAddr(t, "198.51.100.8"), 0},
		"a prefix without it":        {mustPrefix(t, "203.0.113.0/24"), EntryMailSubnet},
		"a prefix from a scan root":  {mustPrefix(t, "198.51.100.0/24"), 0},
		"a prefix through incidents": {mustPrefix(t, "198.51.100.0/24"), EntryIncident},
		"an explicit scan prefix":    {mustPrefix(t, "198.51.100.0/24"), EntryScan},
		"an incident spray prefix":   {mustPrefix(t, "198.51.100.0/24"), EntryIncidentSpray},
		"a central prefix":           {mustPrefix(t, "198.51.100.0/24"), EntryCentral},
		"a timeout prefix":           {mustPrefix(t, "198.51.100.0/24"), EntryChallengeTimeout},
		"a permanent prefix":         {mustPrefix(t, "198.51.100.0/24"), EntryPermblock},
		"a prefix through netblock":  {mustPrefix(t, "198.51.100.0/24"), EntryNetblock},
		"no target":                  {Target{}, 0},
		"a service elsewhere":        {mustService(t, "198.51.100.8", "tcp", 22), 0},
		"the address as IPv6":        {mustAddr(t, "2001:db8::7"), 0},
	} {
		err := BindTarget(c.target, c.via, e)
		if r, _ := ReasonOf(err); r != ReasonAttribution || CauseOf(err) != CauseTargetMismatch {
			t.Errorf("%s: %v, want an attribution refusal naming the mismatch", name, err)
		}
	}
}

// Evidence names the address its parser read; a prefix is a response
// target, never evidence.
func TestMintRefusesAPrefixTarget(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	in.Target = mustPrefix(t, "198.51.100.0/24")
	if _, err := tp.ssh.Mint(in); err == nil {
		t.Fatal("prefix evidence minted")
	} else if r, _ := ReasonOf(err); r != ReasonInvalid {
		t.Fatalf("prefix evidence refused as %v, want invalid", err)
	}
}

// A scan root never widens to a prefix at the ingress: only a range entry
// may act on one (spec 5.13).
func TestIngressRefusesAPrefixFromAnAddressRoot(t *testing.T) {
	f := &ingressFixture{t: t, tp: newTestProducers(t)}
	// Register the entries so an unrelated policy refusal cannot mask binding.
	for _, via := range []Entry{EntryChallengeTimeout, EntryIncident, EntryIncidentSpray, EntryCentral, EntryNetblock, EntryASNCrawl, EntryPermblock} {
		_, err := f.tp.reg.Register(ProducerSpec{ID: ProducerID("binding_" + via.String()), Entry: via,
			Observation: ObservationEventSeq, Checks: []string{"ssh_brute"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.tp.reg.Seal()
	var err error
	f.in, err = NewIngress(f.tp.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.publish()
	wide := f.sub(subSpec{target: "198.51.100.7", cursor: "wide"})
	wide.Kind, wide.Target = KindBlockSubnet, mustPrefix(t, "198.51.100.0/24")
	entries := []Entry{0, EntryScan, EntryIncident, EntryIncidentSpray, EntryCentral, EntryChallengeTimeout, EntryNetblock, EntryPermblock}
	for _, via := range entries {
		wide.Via = via
		err := f.in.Submit(wide)
		if reason, _ := ReasonOf(err); reason != ReasonAttribution || CauseOf(err) != CauseTargetMismatch {
			t.Errorf("prefix through %s: %v", via, err)
		}
	}
	if n := f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonAttribution}); n != uint64(len(entries)) || f.in.Len() != 0 {
		t.Fatalf("attribution refusals = %d, held %d", n, f.in.Len())
	}
	for _, via := range []Entry{EntryMailSubnet, EntryASNCrawl} {
		wide.Via = via
		if err := f.in.Submit(wide); err != nil {
			t.Fatalf("range entry %s refused its contained address: %v", via, err)
		}
	}
	if f.in.Len() != 2 {
		t.Fatalf("held %d, want both permitted range entries", f.in.Len())
	}
}

// A range entry may name several prefixes holding one root; each is its own
// held response, never a duplicate of another target.
func TestIngressHoldsEachTargetOfOneRoot(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	root := f.sub(subSpec{target: "198.51.100.7", cursor: "range"})
	for _, prefix := range []string{"198.51.100.0/24", "198.51.100.0/25"} {
		s := root
		s.Kind, s.Target, s.Via = KindBlockSubnet, mustPrefix(t, prefix), EntryMailSubnet
		if err := f.in.Submit(s); err != nil {
			t.Fatalf("%s: %v", prefix, err)
		}
	}
	if f.in.Len() != 2 || f.in.Stats().Duplicates != 0 {
		t.Fatalf("held %d, duplicates %d; want each prefix held", f.in.Len(), f.in.Stats().Duplicates)
	}
	root.Kind, root.Target, root.Via = KindBlockSubnet, mustPrefix(t, "198.51.100.0/25"), EntryMailSubnet
	if err := f.in.Submit(root); err != nil {
		t.Fatal(err)
	}
	if f.in.Len() != 2 || f.in.Stats().Duplicates != 1 {
		t.Fatalf("held %d, duplicates %d; same target must still coalesce", f.in.Len(), f.in.Stats().Duplicates)
	}
}

func TestBindTargetIPv6(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	in.Target = mustAddr(t, "2001:db8::7")
	e, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []Target{in.Target, mustService(t, "2001:db8::7", "tcp", 22), mustPrefix(t, "2001:db8::/64")} {
		if err := BindTarget(target, EntryMailSubnet, e); err != nil {
			t.Errorf("%s: %v", target.Key(), err)
		}
	}
	for _, target := range []Target{mustAddr(t, "2001:db8::8"), mustPrefix(t, "2001:db8:1::/64"), mustPrefix(t, "198.51.100.0/24")} {
		if err := BindTarget(target, EntryMailSubnet, e); CauseOf(err) != CauseTargetMismatch {
			t.Errorf("%s bound the wrong family or address: %v", target.Key(), err)
		}
	}
	if err := BindTarget(mustPrefix(t, "2001:db8::/64"), EntryCentral, e); CauseOf(err) != CauseTargetMismatch {
		t.Fatalf("central widened an IPv6 root: %v", err)
	}
}

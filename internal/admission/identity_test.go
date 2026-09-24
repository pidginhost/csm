package admission

import "testing"

func mustAddr(t *testing.T, raw string) Target {
	t.Helper()
	tg, err := CanonicalAddress(raw, Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func mustPrefix(t *testing.T, raw string) Target {
	t.Helper()
	tg, err := CanonicalPrefix(raw, Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func mustService(t *testing.T, addr, proto string, port int) Target {
	t.Helper()
	tg, err := CanonicalService(addr, proto, port, Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func testEpisode(t *testing.T, s string) EpisodeID {
	t.Helper()
	e, err := ParseEpisodeID(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const episodeA = "0102030405060708090a0b0c0d0e0f10"

// The ledger stores these IDs. A change to the derivation must bump
// identityVersion and this golden value together.
func TestCandidateAndActionIDsAreFrozen(t *testing.T) {
	key := CandidateKey{Kind: KindBlockIP, Target: mustAddr(t, "192.0.2.1"), Episode: testEpisode(t, episodeA), Generation: 1}
	id, err := key.ID()
	if err != nil || id != "cand_fb12ec00e7378fee71ea3141cc803fb4" {
		t.Fatalf("ID() = %q %v", id, err)
	}
	a2, err := NewAttempt(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := Attempt{ID: "act_7d94f4bf0597bb49b7435b547c3545ba", Candidate: id, Seq: 2, Prev: "act_323946c2fd95219290ddddcc2be42d42"}
	if a2 != want {
		t.Fatalf("NewAttempt(2) = %+v, want %+v", a2, want)
	}
}

func TestCandidateIDDependsOnEveryKeyField(t *testing.T) {
	base := CandidateKey{Kind: KindBlockIP, Target: mustAddr(t, "192.0.2.1"), Episode: testEpisode(t, episodeA), Generation: 1}
	variants := map[string]CandidateKey{}
	k := base
	k.Kind = KindPromote
	variants["kind"] = k
	k = base
	k.Target = mustAddr(t, "192.0.2.2")
	variants["target"] = k
	k = base
	k.Episode = testEpisode(t, "0102030405060708090a0b0c0d0e0f11")
	variants["episode"] = k
	k = base
	k.Generation = 2
	variants["generation"] = k
	baseID, err := base.ID()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[CandidateID]string{baseID: "base"}
	for name, v := range variants {
		id, err := v.ID()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if other, dup := seen[id]; dup {
			t.Errorf("changing %s collides with %s", name, other)
		}
		seen[id] = name
	}
	mapped := base
	mapped.Target = mustAddr(t, "::ffff:192.0.2.1")
	if id, _ := mapped.ID(); id != baseID {
		t.Error("an IPv4-mapped spelling of the same address changes the candidate ID")
	}
}

func TestValidateKindTarget(t *testing.T) {
	addr := mustAddr(t, "192.0.2.1")
	prefix := mustPrefix(t, "198.51.100.0/24")
	svc := mustService(t, "192.0.2.1", "tcp", 22)
	ok := map[Kind]Target{KindBlockIP: addr, KindPromote: addr, KindChallenge: addr, KindBlockService: svc, KindBlockSubnet: prefix}
	for k, tg := range ok {
		if err := ValidateKindTarget(k, tg); err != nil {
			t.Errorf("%s on %s: %v", k, tg.Key(), err)
		}
	}
	bad := []struct {
		k  Kind
		tg Target
	}{
		{KindBlockIP, prefix}, {KindBlockIP, svc}, {KindPromote, prefix},
		{KindChallenge, svc}, {KindBlockService, addr}, {KindBlockSubnet, addr},
		{KindBlockSubnet, svc}, {0, addr}, {kindEnd, addr}, {KindBlockIP, Target{}},
	}
	for _, tc := range bad {
		err := ValidateKindTarget(tc.k, tc.tg)
		wantReason(t, tc.k.String()+" on "+tc.tg.Key(), err, ReasonInvalid)
	}
}

func TestCandidateKeyRefusesMissingEpisodeOrGeneration(t *testing.T) {
	addr := mustAddr(t, "192.0.2.1")
	for name, key := range map[string]CandidateKey{
		"zero episode":    {Kind: KindBlockIP, Target: addr, Generation: 1},
		"zero generation": {Kind: KindBlockIP, Target: addr, Episode: testEpisode(t, episodeA)},
		"wrong target":    {Kind: KindBlockSubnet, Target: addr, Episode: testEpisode(t, episodeA), Generation: 1},
	} {
		_, err := key.ID()
		wantReason(t, name, err, ReasonInvalid)
	}
}

func TestAttemptChain(t *testing.T) {
	id, _ := CandidateKey{Kind: KindBlockIP, Target: mustAddr(t, "192.0.2.1"), Episode: testEpisode(t, episodeA), Generation: 1}.ID()
	a1, err := NewAttempt(id, 1)
	if err != nil || a1.Prev != "" || a1.Seq != 1 {
		t.Fatalf("first attempt = %+v %v", a1, err)
	}
	a2, _ := NewAttempt(id, 2)
	if a2.Prev != a1.ID || a2.ID == a1.ID {
		t.Fatalf("second attempt = %+v does not link to %s", a2, a1.ID)
	}
	if again, _ := NewAttempt(id, 2); again != a2 {
		t.Error("attempt derivation is not stable")
	}
	for name, a := range map[string]Attempt{
		"relinked prev":       {ID: a2.ID, Candidate: id, Seq: 2, Prev: "act_00000000000000000000000000000000"},
		"renumbered":          {ID: a2.ID, Candidate: id, Seq: 3, Prev: a2.ID},
		"foreign candidate":   {ID: a1.ID, Candidate: "cand_00000000000000000000000000000000", Seq: 1},
		"malformed candidate": {ID: a1.ID, Candidate: "cand_X", Seq: 1},
	} {
		wantReason(t, name, a.Validate(), ReasonInvalid)
	}
	if verr := a2.Validate(); verr != nil {
		t.Errorf("a derived attempt does not validate: %v", verr)
	}
	_, err = NewAttempt(id, 0)
	wantReason(t, "sequence 0", err, ReasonInvalid)
}

func TestParseIDs(t *testing.T) {
	for _, s := range []string{"", "cand_", "cand_FB12EC00E7378FEE71EA3141CC803FB4", "cand_fb12ec00e7378fee71ea3141cc803fb", "act_fb12ec00e7378fee71ea3141cc803fb4x", "cand_fb12ec00e7378fee71ea3141cc803fb4 "} {
		_, err := ParseCandidateID(s)
		wantReason(t, "ParseCandidateID("+s+")", err, ReasonInvalid)
	}
	if _, err := ParseCandidateID("cand_fb12ec00e7378fee71ea3141cc803fb4"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"cand_323946c2fd95219290ddddcc2be42d42", "act_323946c2fd95219290ddddcc2be42d4g"} {
		_, err := ParseActionID(s)
		wantReason(t, "ParseActionID("+s+")", err, ReasonInvalid)
	}
	if _, err := ParseActionID("act_323946c2fd95219290ddddcc2be42d42"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"00000000000000000000000000000000", "0102030405060708090A0B0C0D0E0F10", "01"} {
		_, err := ParseEpisodeID(s)
		wantReason(t, "ParseEpisodeID("+s+")", err, ReasonInvalid)
	}
}

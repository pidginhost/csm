package admission

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Checks, daemon, firewall and store all import this package. Any internal
// or third-party import here risks a cycle through config or alert.
func TestPackageImportsOnlyStandardLibrary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s", name, path)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no production files checked")
	}
}

// The ledger persists these numbers. Renumbering one silently rewrites every
// stored record that carries it.
func TestPersistedEnumValuesAreFrozen(t *testing.T) {
	frozen := map[string][2]uint8{
		"EffectAddress":               {uint8(EffectAddress), 1},
		"EffectService":               {uint8(EffectService), 2},
		"EffectPrefix":                {uint8(EffectPrefix), 3},
		"EffectChallenge":             {uint8(EffectChallenge), 4},
		"EntryChallengeTimeout":       {uint8(EntryChallengeTimeout), 2},
		"EntryIncident":               {uint8(EntryIncident), 3},
		"EntryIncidentSpray":          {uint8(EntryIncidentSpray), 4},
		"EntryCentral":                {uint8(EntryCentral), 5},
		"EntryNetblock":               {uint8(EntryNetblock), 6},
		"EntryASNCrawl":               {uint8(EntryASNCrawl), 7},
		"EntryMailSubnet":             {uint8(EntryMailSubnet), 8},
		"DispositionDeferred":         {uint8(DispositionDeferred), 1},
		"DispositionRefused":          {uint8(DispositionRefused), 2},
		"DispositionWithheld":         {uint8(DispositionWithheld), 3},
		"DispositionDropped":          {uint8(DispositionDropped), 4},
		"ReasonSetFull":               {uint8(ReasonSetFull), 2},
		"ReasonStorageShare":          {uint8(ReasonStorageShare), 3},
		"ReasonEngineUnavailable":     {uint8(ReasonEngineUnavailable), 4},
		"ReasonPendingRecovery":       {uint8(ReasonPendingRecovery), 5},
		"ReasonProtected":             {uint8(ReasonProtected), 6},
		"ReasonAttribution":           {uint8(ReasonAttribution), 7},
		"ReasonInvalid":               {uint8(ReasonInvalid), 8},
		"ReasonPolicy":                {uint8(ReasonPolicy), 9},
		"ReasonStaleIdentity":         {uint8(ReasonStaleIdentity), 10},
		"ReasonExistingEffect":        {uint8(ReasonExistingEffect), 11},
		"ReasonCollateral":            {uint8(ReasonCollateral), 12},
		"ReasonBreaker":               {uint8(ReasonBreaker), 13},
		"ReasonEnvelopeNoAlternative": {uint8(ReasonEnvelopeNoAlternative), 14},
		"ReasonQueueOverflow":         {uint8(ReasonQueueOverflow), 16},
		"ReasonStale":                 {uint8(ReasonStale), 17},

		"SeverityWarning":              {uint8(SeverityWarning), 1},
		"SeverityHigh":                 {uint8(SeverityHigh), 2},
		"SeverityCritical":             {uint8(SeverityCritical), 3},
		"ClassC2":                      {uint8(ClassC2), 2},
		"ClassC1":                      {uint8(ClassC1), 1},
		"ClassC3":                      {uint8(ClassC3), 3},
		"FamilyNone":                   {uint8(FamilyNone), 0},
		"FamilyHTTP":                   {uint8(FamilyHTTP), 1},
		"FamilyPanel":                  {uint8(FamilyPanel), 2},
		"FamilyMail":                   {uint8(FamilyMail), 3},
		"FamilySSH":                    {uint8(FamilySSH), 4},
		"FamilyFTP":                    {uint8(FamilyFTP), 5},
		"FamilyNetwork":                {uint8(FamilyNetwork), 6},
		"FamilyReputation":             {uint8(FamilyReputation), 7},
		"FamilyDerived":                {uint8(FamilyDerived), 8},
		"BasisNone":                    {uint8(BasisNone), 0},
		"BasisIntel":                   {uint8(BasisIntel), 1},
		"BasisLocal":                   {uint8(BasisLocal), 2},
		"BasisCompromise":              {uint8(BasisCompromise), 3},
		"KindBlockIP":                  {uint8(KindBlockIP), 1},
		"KindBlockService":             {uint8(KindBlockService), 2},
		"KindBlockSubnet":              {uint8(KindBlockSubnet), 3},
		"KindPromote":                  {uint8(KindPromote), 4},
		"KindChallenge":                {uint8(KindChallenge), 5},
		"EntryScan":                    {uint8(EntryScan), 1},
		"EntryPermblock":               {uint8(EntryPermblock), 9},
		"ReasonCeiling":                {uint8(ReasonCeiling), 1},
		"ReasonIngressInterruption":    {uint8(ReasonIngressInterruption), 18},
		"ReasonUnsupportedContainment": {uint8(ReasonUnsupportedContainment), 15},
	}
	for name, v := range frozen {
		if v[0] != v[1] {
			t.Errorf("%s = %d, frozen at %d", name, v[0], v[1])
		}
	}
}

func TestSeverityAndClassValidity(t *testing.T) {
	for _, s := range []Severity{0, 4, 255} {
		if s.Valid() {
			t.Errorf("Severity(%d) is valid", s)
		}
	}
	for _, c := range []Class{0, 4} {
		if c.Valid() {
			t.Errorf("Class(%d) is valid", c)
		}
	}
	if (Tier{Class: ClassC2}).Valid() || (Tier{Severity: SeverityHigh}).Valid() {
		t.Error("a tier with a zero half is valid")
	}
}

func TestTierOrdersClassBeforeSeverity(t *testing.T) {
	c1crit := Tier{ClassC1, SeverityCritical}
	c2warn := Tier{ClassC2, SeverityWarning}
	c2high := Tier{ClassC2, SeverityHigh}
	cases := []struct {
		a, b Tier
		less bool
	}{
		{c1crit, c2warn, true},
		{c2warn, c1crit, false},
		{c2warn, c2high, true},
		{c2high, c2warn, false},
		{c2high, c2high, false},
	}
	for _, tc := range cases {
		if got := tc.a.Less(tc.b); got != tc.less {
			t.Errorf("%v.Less(%v) = %v, want %v", tc.a, tc.b, got, tc.less)
		}
	}
}

func TestFamilyProperties(t *testing.T) {
	want := map[Family][2]bool{ // LocalAttack, Independent
		FamilyNone:       {false, false},
		FamilyHTTP:       {true, true},
		FamilyPanel:      {true, true},
		FamilyMail:       {true, true},
		FamilySSH:        {true, true},
		FamilyFTP:        {true, true},
		FamilyNetwork:    {true, true},
		FamilyReputation: {false, true},
		FamilyDerived:    {false, false},
	}
	if len(want) != int(familyEnd) {
		t.Fatalf("table covers %d families, package defines %d", len(want), familyEnd)
	}
	seen := map[string]bool{}
	for f, w := range want {
		if f.LocalAttack() != w[0] || f.Independent() != w[1] {
			t.Errorf("%s: LocalAttack=%v Independent=%v, want %v %v", f, f.LocalAttack(), f.Independent(), w[0], w[1])
		}
		if seen[f.String()] || strings.HasPrefix(f.String(), "family(") {
			t.Errorf("family %d has a duplicate or missing name %q", f, f)
		}
		seen[f.String()] = true
	}
	if familyEnd.Valid() {
		t.Error("the end sentinel is a valid family")
	}
}

func TestValidPolicy(t *testing.T) {
	ok := [][2]uint8{
		{uint8(FamilyNone), uint8(BasisNone)},
		{uint8(FamilyReputation), uint8(BasisIntel)},
		{uint8(FamilyDerived), uint8(BasisIntel)},
		{uint8(FamilySSH), uint8(BasisLocal)},
		{uint8(FamilyMail), uint8(BasisCompromise)},
		{uint8(FamilyNetwork), uint8(BasisCompromise)},
	}
	bad := [][2]uint8{
		{uint8(FamilyNone), uint8(BasisLocal)},
		{uint8(FamilySSH), uint8(BasisNone)},
		{uint8(FamilySSH), uint8(BasisIntel)},
		{uint8(FamilyReputation), uint8(BasisLocal)},
		{uint8(FamilyDerived), uint8(BasisCompromise)},
		{uint8(familyEnd), uint8(BasisLocal)},
		{uint8(FamilyHTTP), uint8(basisEnd)},
	}
	for _, p := range ok {
		if err := ValidPolicy(Family(p[0]), Basis(p[1])); err != nil {
			t.Errorf("ValidPolicy(%s, %s) = %v, want nil", Family(p[0]), Basis(p[1]), err)
		}
	}
	for _, p := range bad {
		if err := ValidPolicy(Family(p[0]), Basis(p[1])); err == nil {
			t.Errorf("ValidPolicy(%d, %d) accepted", p[0], p[1])
		}
	}
}

func TestBasisClass(t *testing.T) {
	for b, want := range map[Basis]Class{BasisIntel: ClassC1, BasisLocal: ClassC2, BasisCompromise: ClassC3} {
		if got, ok := b.Class(); !ok || got != want {
			t.Errorf("%s.Class() = %v %v, want %v", b, got, ok, want)
		}
	}
	if _, ok := BasisNone.Class(); ok {
		t.Error("BasisNone supports a class")
	}
}

func TestKindEffect(t *testing.T) {
	want := map[Kind]Effect{
		KindBlockIP:      EffectAddress,
		KindPromote:      EffectAddress,
		KindBlockService: EffectService,
		KindBlockSubnet:  EffectPrefix,
		KindChallenge:    EffectChallenge,
	}
	if len(want) != int(kindEnd)-1 {
		t.Fatalf("table covers %d kinds, package defines %d", len(want), kindEnd-1)
	}
	for k, e := range want {
		if k.Effect() != e || !e.Valid() {
			t.Errorf("%s.Effect() = %s, want valid %s", k, k.Effect(), e)
		}
	}
	if Kind(0).Valid() || kindEnd.Valid() {
		t.Error("an out-of-range kind is valid")
	}
	if Effect(0).Valid() || effectEnd.Valid() || Kind(0).Effect().Valid() {
		t.Error("an out-of-range effect is valid")
	}
}

func TestAdmissionEffectAndDispositionValidity(t *testing.T) {
	effects := [...]string{"", "address", "service", "prefix", "challenge"}
	dispositions := [...]string{"", "deferred", "refused", "withheld", "dropped"}
	for value := 0; value <= 255; value++ {
		e, d := Effect(value), Disposition(value)
		valid := value >= 1 && value <= 4
		if e.Valid() != valid || d.Valid() != valid {
			t.Errorf("value %d: effect valid %v, disposition valid %v, want %v", value, e.Valid(), d.Valid(), valid)
		}
		wantEffect, wantDisposition := fmt.Sprintf("effect(%d)", value), fmt.Sprintf("disposition(%d)", value)
		if valid {
			wantEffect, wantDisposition = effects[value], dispositions[value]
		}
		if e.String() != wantEffect || d.String() != wantDisposition {
			t.Errorf("value %d: effect %q, disposition %q, want %q, %q", value, e, d, wantEffect, wantDisposition)
		}
	}
}

// The tokens are the operator-visible vocabulary of the response safety
// design; status, audit and alerts print them.
func TestReasonVocabulary(t *testing.T) {
	groups := map[Disposition][]string{
		DispositionDeferred: {"ceiling", "set_full", "storage_share", "engine_unavailable", "pending_recovery"},
		DispositionRefused:  {"protected", "attribution", "invalid", "policy", "stale_identity", "existing_effect"},
		DispositionWithheld: {"collateral", "breaker", "envelope_no_alternative", "unsupported_containment"},
		DispositionDropped:  {"queue_overflow", "stale", "ingress_interruption"},
	}
	got := map[Disposition][]string{}
	for r := ReasonCeiling; r < reasonEnd; r++ {
		if !r.Disposition().Valid() {
			t.Errorf("%s has no valid disposition", r)
		}
		got[r.Disposition()] = append(got[r.Disposition()], r.String())
	}
	for d, names := range groups {
		if fmt.Sprint(got[d]) != fmt.Sprint(names) {
			t.Errorf("%s reasons = %v, want %v", d, got[d], names)
		}
	}
	if len(got) != len(groups) {
		t.Errorf("reasons fall into %d groups, want %d", len(got), len(groups))
	}
	if Reason(0).Valid() || reasonEnd.Valid() || reasonEnd.Disposition() != 0 {
		t.Error("an out-of-range reason is valid or grouped")
	}
	if Disposition(0).Valid() || dispositionEnd.Valid() {
		t.Error("an out-of-range disposition is valid")
	}
}

func TestReasonOfUnwrapsAdmissionErrors(t *testing.T) {
	err := fmt.Errorf("context: %w", refuse(ReasonProtected, "loopback address"))
	if r, ok := ReasonOf(err); !ok || r != ReasonProtected {
		t.Fatalf("ReasonOf = %v %v, want protected", r, ok)
	}
	if got := err.Error(); got != "context: protected: loopback address" {
		t.Errorf("error text = %q", got)
	}
	if _, ok := ReasonOf(errors.New("plain")); ok {
		t.Error("a plain error carries a reason")
	}
}

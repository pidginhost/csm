package learn

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

// fakeView is an in-memory LedgerReader.
type fakeView struct {
	aliases  map[Digest]uint64
	clusters map[uint64]Cluster
	targets  map[Digest]Target
	usage    map[int]Usage
	operator Usage
	err      error
	readErr  func(kind string, key any) error
}

func (v *fakeView) readError(kind string, key any) error {
	if v.readErr != nil {
		return v.readErr(kind, key)
	}
	return v.err
}

func newView() *fakeView {
	return &fakeView{aliases: map[Digest]uint64{}, clusters: map[uint64]Cluster{}, targets: map[Digest]Target{}, usage: map[int]Usage{}}
}

// cluster adds a live cluster whose anchor is its own alias.
func (v *fakeView) cluster(id uint64, anchor Digest, t int32, uids ...int) {
	v.clusters[id] = Cluster{ID: id, Anchor: anchor, UIDs: uids, Aliases: []Digest{anchor}}
	v.aliases[anchor] = id
	v.targets[anchor] = Target{Digest: anchor, ClusterID: id, T: t, Phase: PhaseIdle}
}

func (v *fakeView) Alias(d Digest) (uint64, bool, error) {
	id, ok := v.aliases[d]
	return id, ok, v.readError("alias", d)
}

func (v *fakeView) Cluster(id uint64) (Cluster, bool, error) {
	c, ok := v.clusters[id]
	return c, ok, v.readError("cluster", id)
}

func (v *fakeView) Target(d Digest) (Target, bool, error) {
	t, ok := v.targets[d]
	return t, ok, v.readError("target", d)
}

func (v *fakeView) Usage(uid int, operator bool) (Usage, error) {
	if operator {
		return v.operator, v.readError("usage", uid)
	}
	return v.usage[uid], v.readError("usage", uid)
}

func inspection(results ...Result) Inspection {
	return Inspection{Results: results, Distinct: len(results)}
}

func hitResult(q, stored Digest, prob float64) Result {
	return Result{Queried: q, Stored: stored, Found: true, Confirmed: true, Prob: prob, Value: 2, Flag: 1}
}

func missResult(q Digest) Result { return Result{Queried: q} }

var tenant = Source{UID: 1001, BodyLen: 100}

func assign(t *testing.T, insp Inspection, src Source, v *fakeView, gaps map[uint64]bool) Admission {
	t.Helper()
	a, err := Assign(insp, src, v, gaps)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAssignAliasFirst(t *testing.T) {
	v := newView()
	v.cluster(5, digest('a'), 2, 2002)
	v.cluster(9, digest('b'), 2, 2002)
	v.aliases[digest('c')] = 5
	a := assign(t, inspection(hitResult(digest('c'), digest('b'), 1)), tenant, v, nil)
	want := []Join{{ClusterID: 5, NewT: 4}}
	if !reflect.DeepEqual(a.Joins, want) || a.Seed != nil || len(a.Skips) != 0 {
		t.Fatalf("got %+v", a)
	}
	// An alias holds even when storage has lost every anchor.
	a = assign(t, inspection(missResult(digest('c'))), tenant, v, nil)
	if !reflect.DeepEqual(a.Joins, want) || a.Seed != nil {
		t.Fatalf("alias with a miss: %+v", a)
	}
}

func TestAssignJoinAtBoundary(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	a := assign(t, inspection(hitResult(digest('b'), digest('a'), 0.75)), tenant, v, nil)
	if !reflect.DeepEqual(a.Joins, []Join{{ClusterID: 1, Aliases: []Digest{digest('b')}, NewT: 4}}) {
		t.Fatalf("0.75 did not join: %+v", a)
	}
	a = assign(t, inspection(hitResult(digest('b'), digest('a'), 0.7499)), tenant, v, nil)
	if len(a.Joins) != 0 || a.Seed != nil || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('b'), Reason: SkipBelowJoin}}) {
		t.Fatalf("0.7499: %+v", a)
	}
}

func TestAssignSeedSingleDigestMiss(t *testing.T) {
	v := newView()
	a := assign(t, inspection(missResult(digest('a'))), tenant, v, nil)
	if a.Seed == nil || *a.Seed != (Seed{Anchor: digest('a'), T: 2}) || len(a.Joins) != 0 || a.Defer {
		t.Fatalf("got %+v", a)
	}
	a = assign(t, inspection(missResult(digest('a'))), Source{Operator: true, MarkID: "req-1", BodyLen: 100}, v, nil)
	if a.Seed == nil || a.Seed.T != 18 {
		t.Fatalf("operator seed %+v", a)
	}
}

func TestAssignNoSeedForMultipart(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	a := assign(t, inspection(hitResult(digest('b'), digest('a'), 0.9), missResult(digest('c'))), tenant, v, nil)
	if a.Seed != nil || len(a.Joins) != 1 || a.Joins[0].ClusterID != 1 {
		t.Fatalf("got %+v", a)
	}
	if !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('c'), Reason: SkipMultipartSeed}}) {
		t.Fatalf("skips %+v", a.Skips)
	}
	a = assign(t, inspection(missResult(digest('d')), missResult(digest('e'))), tenant, v, nil)
	if a.Seed != nil || len(a.Skips) != 2 {
		t.Fatalf("two misses seeded: %+v", a)
	}
}

func TestAssignOneVotePerUIDPerCluster(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	// Two parts (or two mailboxes' copies) of one report land on one cluster.
	report := inspection(hitResult(digest('b'), digest('a'), 0.9), hitResult(digest('c'), digest('a'), 0.8), hitResult(digest('a'), digest('a'), 1))
	a := assign(t, report, tenant, v, nil)
	if !reflect.DeepEqual(a.Joins, []Join{{ClusterID: 1, Aliases: []Digest{digest('b'), digest('c')}, NewT: 4}}) || len(a.Skips) != 0 {
		t.Fatalf("first report: %+v", a)
	}
	// Once the UID has voted, repeats gain nothing and add no aliases.
	v.clusters[1] = Cluster{ID: 1, Anchor: digest('a'), UIDs: []int{2002, 1001}, Aliases: []Digest{digest('a'), digest('b'), digest('c')}}
	a = assign(t, inspection(hitResult(digest('d'), digest('a'), 0.9), hitResult(digest('a'), digest('a'), 1)), tenant, v, nil)
	if len(a.Joins) != 0 || a.Seed != nil || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('d'), Reason: SkipDuplicate}, {Digest: digest('a'), Reason: SkipDuplicate}}) {
		t.Fatalf("repeat: %+v", a)
	}
}

func TestAssignOperatorMarkOncePerCluster(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 4, 2002, 2003)
	op := Source{Operator: true, MarkID: "req-1", BodyLen: 100}
	a := assign(t, inspection(hitResult(digest('a'), digest('a'), 1), hitResult(digest('b'), digest('a'), 0.9)), op, v, nil)
	if !reflect.DeepEqual(a.Joins, []Join{{ClusterID: 1, Aliases: []Digest{digest('b')}, NewT: 22}}) {
		t.Fatalf("got %+v", a)
	}
	c := v.clusters[1]
	c.Marks = []string{"req-1"}
	v.clusters[1] = c
	a = assign(t, inspection(hitResult(digest('a'), digest('a'), 1)), op, v, nil)
	if len(a.Joins) != 0 || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('a'), Reason: SkipDuplicate}}) {
		t.Fatalf("same mark again: %+v", a)
	}
}

func TestAssignZeroTargetDefersAndQueuesDelete(t *testing.T) {
	v := newView()
	v.targets[digest('z')] = Target{Digest: digest('z'), ClusterID: 3, T: 0}
	a := assign(t, inspection(hitResult(digest('b'), digest('z'), 0.9)), tenant, v, nil)
	if !a.Defer || !reflect.DeepEqual(a.DeleteZero, []Digest{digest('z')}) || len(a.Joins) != 0 || a.Seed != nil {
		t.Fatalf("got %+v", a)
	}
}

func TestAssignUnknownDigestMismatch(t *testing.T) {
	v := newView()
	a := assign(t, inspection(hitResult(digest('b'), digest('u'), 0.9)), tenant, v, nil)
	if !a.Defer || !reflect.DeepEqual(a.Mismatch, []Digest{digest('u')}) || len(a.Joins) != 0 || a.Seed != nil || len(a.DeleteZero) != 0 {
		t.Fatalf("got %+v", a)
	}
	// An alias naming a cluster the ledger lacks is a mismatch too.
	v.aliases[digest('c')] = 7
	a = assign(t, inspection(missResult(digest('c'))), tenant, v, nil)
	if !a.Defer || !reflect.DeepEqual(a.Mismatch, []Digest{digest('c')}) || len(a.Joins) != 0 {
		t.Fatalf("dangling alias: %+v", a)
	}
}

func TestAssignOverflowRejectsAll(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2147483646, 2002)
	v.cluster(2, digest('c'), 2, 2002)
	a := assign(t, inspection(hitResult(digest('a'), digest('a'), 1), hitResult(digest('c'), digest('c'), 1)), tenant, v, nil)
	if len(a.Joins) != 0 || a.Seed != nil {
		t.Fatalf("joined past the limit: %+v", a)
	}
	if !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('a'), Reason: SkipOverflow}, {Digest: digest('c'), Reason: SkipOverflow}}) {
		t.Fatalf("skips %+v", a.Skips)
	}
}

func TestAssignOverflowDiscardsEarlierJoin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source Source
		weight int32
	}{
		{"tenant", tenant, UIDWeight},
		{"operator", Source{Operator: true, MarkID: "req-1"}, OperatorWeight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			v.cluster(1, digest('a'), 2, 2002)
			v.cluster(2, digest('c'), math.MaxInt32-1-tc.weight, 2002)
			report := inspection(hitResult(digest('b'), digest('a'), 1), hitResult(digest('d'), digest('c'), 1))
			want := Admission{Joins: []Join{
				{ClusterID: 1, Aliases: []Digest{digest('b')}, NewT: 2 + tc.weight},
				{ClusterID: 2, Aliases: []Digest{digest('d')}, NewT: math.MaxInt32 - 1},
			}}
			if a := assign(t, report, tc.source, v, nil); !reflect.DeepEqual(a, want) {
				t.Fatalf("largest representable target: got %+v, want %+v", a, want)
			}
			v.cluster(2, digest('c'), math.MaxInt32-tc.weight+1, 2002)
			want = Admission{Skips: []Skip{{Digest: digest('b'), Reason: SkipOverflow}, {Digest: digest('d'), Reason: SkipOverflow}}}
			if a := assign(t, report, tc.source, v, nil); !reflect.DeepEqual(a, want) {
				t.Fatalf("overflow in the second cluster: got %+v, want %+v", a, want)
			}
		})
	}
}

func TestAssignDefersDuringGap(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	v.cluster(2, digest('c'), 2, 2002)
	v.aliases[digest('d')] = 2
	gaps := map[uint64]bool{1: true}
	if a := assign(t, inspection(hitResult(digest('b'), digest('a'), 0.9)), tenant, v, gaps); !a.Defer || len(a.Joins) != 0 {
		t.Fatalf("match on the gap cluster: %+v", a)
	}
	// A miss may be the anchor that is missing: never seed during a gap.
	if a := assign(t, inspection(missResult(digest('e'))), tenant, v, gaps); !a.Defer || a.Seed != nil {
		t.Fatalf("seed during a gap: %+v", a)
	}
	if a := assign(t, inspection(hitResult(digest('f'), digest('c'), 0.9)), tenant, v, gaps); !a.Defer {
		t.Fatalf("unseen alias resolved during a gap: %+v", a)
	}
	a := assign(t, inspection(missResult(digest('d'))), tenant, v, gaps)
	if a.Defer || !reflect.DeepEqual(a.Joins, []Join{{ClusterID: 2, NewT: 4}}) {
		t.Fatalf("existing alias on another cluster: %+v", a)
	}
	if a := assign(t, inspection(hitResult(digest('a'), digest('a'), 1)), tenant, v, gaps); !a.Defer {
		t.Fatalf("alias on the gap cluster joined: %+v", a)
	}
}

func TestAssignBelowJoinWaitsForGapRepair(t *testing.T) {
	for _, stored := range []Digest{digest('a'), digest('c')} {
		t.Run(string(stored[:1]), func(t *testing.T) {
			v := newView()
			v.cluster(1, digest('a'), 2, 2002)
			v.cluster(2, digest('c'), 2, 2002)
			report := inspection(hitResult(digest('b'), stored, 0.5))
			if a := assign(t, report, tenant, v, map[uint64]bool{1: true}); !reflect.DeepEqual(a, Admission{Defer: true}) {
				t.Fatalf("low-probability hit during a gap: %+v", a)
			}
			mixed := inspection(missResult(digest('c')), report.Results[0])
			if a := assign(t, mixed, tenant, v, map[uint64]bool{1: true}); !reflect.DeepEqual(a, Admission{Defer: true}) {
				t.Fatalf("mixed report during a gap: %+v", a)
			}
			// Restoring the missing anchor can change the best match.
			repaired := inspection(hitResult(digest('b'), digest('a'), 0.9))
			want := Admission{Joins: []Join{{ClusterID: 1, Aliases: []Digest{digest('b')}, NewT: 4}}}
			if a := assign(t, repaired, tenant, v, nil); !reflect.DeepEqual(a, want) {
				t.Fatalf("reinspection after repair: got %+v, want %+v", a, want)
			}
			want = Admission{Skips: []Skip{{Digest: digest('b'), Reason: SkipBelowJoin}}}
			if a := assign(t, report, tenant, v, nil); !reflect.DeepEqual(a, want) {
				t.Fatalf("low-probability hit without a gap: got %+v, want %+v", a, want)
			}
		})
	}
}

func TestAssignClearedGapsAllowFreshAssignments(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	gaps := map[uint64]bool{1: false}
	for _, tc := range []struct {
		name   string
		report Inspection
		want   Admission
	}{
		{"join", inspection(hitResult(digest('b'), digest('a'), 0.9)), Admission{Joins: []Join{{ClusterID: 1, Aliases: []Digest{digest('b')}, NewT: 4}}}},
		{"seed", inspection(missResult(digest('b'))), Admission{Seed: &Seed{Anchor: digest('b'), T: 2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a := assign(t, tc.report, tenant, v, gaps); !reflect.DeepEqual(a, tc.want) {
				t.Fatalf("cleared gap: got %+v, want %+v", a, tc.want)
			}
		})
	}
}

func TestAssignNoDigest(t *testing.T) {
	a := assign(t, inspection(), tenant, newView(), nil)
	if !reflect.DeepEqual(a.Skips, []Skip{{Reason: SkipNoDigest}}) || len(a.Joins) != 0 || a.Seed != nil || a.Defer {
		t.Fatalf("got %+v", a)
	}
}

func TestAssignCapacity(t *testing.T) {
	v := newView()
	v.cluster(1, digest('a'), 2, 2002)
	v.usage[1001] = Usage{BodyBytes: AccountBodyBytes - 50}
	a := assign(t, inspection(missResult(digest('b'))), tenant, v, nil)
	if a.Seed != nil || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('b'), Reason: SkipAccountCapacity}}) {
		t.Fatalf("body allowance: %+v", a)
	}
	v.usage[1001] = Usage{Aliases: AccountAliases}
	a = assign(t, inspection(hitResult(digest('c'), digest('a'), 0.9)), tenant, v, nil)
	if len(a.Joins) != 0 || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('c'), Reason: SkipAccountCapacity}}) {
		t.Fatalf("alias allowance: %+v", a)
	}
	// A vote that adds no alias still counts at the alias limit.
	if a = assign(t, inspection(hitResult(digest('a'), digest('a'), 1)), tenant, v, nil); len(a.Joins) != 1 {
		t.Fatalf("aliasless vote refused: %+v", a)
	}
	v.operator = Usage{BodyBytes: OperatorBodyBytes}
	a = assign(t, inspection(missResult(digest('d'))), Source{Operator: true, MarkID: "req-1", BodyLen: 1}, v, nil)
	if a.Seed != nil || !reflect.DeepEqual(a.Skips, []Skip{{Digest: digest('d'), Reason: SkipOperatorCapacity}}) {
		t.Fatalf("operator allowance: %+v", a)
	}
}

func TestAssignLedgerErrorDefers(t *testing.T) {
	v := newView()
	v.err = errors.New("read failed")
	if _, err := Assign(inspection(missResult(digest('a'))), tenant, v, nil); err == nil {
		t.Fatal("ledger read error ignored")
	}
}

func TestAssignLedgerErrorsDiscardAdmission(t *testing.T) {
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name   string
		kind   string
		key    any
		report Inspection
	}{
		{"alias", "alias", digest('b'), inspection(missResult(digest('b')))},
		{"matched target", "target", digest('a'), inspection(hitResult(digest('b'), digest('a'), 1))},
		{"cluster after join", "cluster", uint64(2), inspection(missResult(digest('a')), missResult(digest('c')))},
		{"anchor target after join", "target", digest('c'), inspection(missResult(digest('a')), missResult(digest('c')))},
		{"usage after joins", "usage", tenant.UID, inspection(missResult(digest('a')), missResult(digest('c')))},
		{"usage after seed", "usage", tenant.UID, inspection(missResult(digest('b')))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newView()
			v.cluster(1, digest('a'), 2, 2002)
			v.cluster(2, digest('c'), 2, 2002)
			v.readErr = func(kind string, key any) error {
				if kind == tc.kind && key == tc.key {
					return readErr
				}
				return nil
			}
			a, err := Assign(tc.report, tenant, v, nil)
			if !errors.Is(err, readErr) || !reflect.DeepEqual(a, Admission{}) {
				t.Fatalf("ledger failure: admission %+v, error %v", a, err)
			}
		})
	}
}

package learn

import (
	"errors"
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
	return id, ok, v.err
}

func (v *fakeView) Cluster(id uint64) (Cluster, bool, error) {
	c, ok := v.clusters[id]
	return c, ok, v.err
}

func (v *fakeView) Target(d Digest) (Target, bool, error) {
	t, ok := v.targets[d]
	return t, ok, v.err
}

func (v *fakeView) Usage(uid int, operator bool) (Usage, error) {
	if operator {
		return v.operator, v.err
	}
	return v.usage[uid], v.err
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

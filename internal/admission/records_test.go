package admission

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestInventoryRoundTripsAndRefusesTampering(t *testing.T) {
	inv := testInventory(t)
	data, err := inv.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalInventory(data)
	if err != nil || !reflect.DeepEqual(back, inv) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	empty, _ := NewInventory(nil, nil)
	emptyData, err := empty.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err = UnmarshalInventory(emptyData); err != nil || !reflect.DeepEqual(back, empty) {
		t.Fatalf("empty round trip = %+v, %v", back, err)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":    func() []byte { d := bytes.Clone(data); d[4] ^= 1; return d }(),
		"unlisted owner":  resealForTest(bytes.Replace(body, []byte(`"alice.example":"alice"`), []byte(`"alice.example":"carol"`), 1)),
		"zero generation": resealForTest(bytes.Replace(body, []byte(`"alice":1`), []byte(`"alice":0`), 1)),
		"no domains":      resealForTest(bytes.Replace(body, []byte(`,"domains":{`), []byte(`,"domainz":{`), 1)),
	} {
		if _, err := UnmarshalInventory(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestReportLinksAreBoundedAndSorted(t *testing.T) {
	var r ReportLinks
	var changed bool
	var err error
	for i := MaxReportLinks + 2; i > 0; i-- {
		if r, changed, err = r.Add(fmt.Sprintf("%016x", i)); err != nil || !changed {
			t.Fatalf("add %d: changed %v, %v", i, changed, err)
		}
	}
	if len(r.Links) != MaxReportLinks || r.Dropped != 2 {
		t.Fatalf("links %d dropped %d", len(r.Links), r.Dropped)
	}
	for i := 1; i < len(r.Links); i++ {
		if r.Links[i-1] >= r.Links[i] {
			t.Fatalf("links unsorted: %v", r.Links)
		}
	}
	if again, changed, _ := r.Add(r.Links[0]); changed || !reflect.DeepEqual(again, r) {
		t.Fatal("a repeated link changed the record")
	}
	if _, _, err = r.Add("NOT-A-FINDING-ID"); err == nil {
		t.Fatal("malformed finding ID accepted")
	}
	full := ReportLinks{Links: r.Links, Dropped: ^uint32(0)}
	if again, changed, _ := full.Add("ffffffffffffffff"); changed || again.Dropped != ^uint32(0) {
		t.Fatal("dropped counter wrapped")
	}
	data, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := UnmarshalReportLinks(data); err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"dropped while room": resealForTest([]byte(`{"v":1,"links":["0000000000000001"],"dropped":1}`)),
		"unsorted":           resealForTest([]byte(`{"v":1,"links":["0000000000000002","0000000000000001"]}`)),
		"upper case":         resealForTest([]byte(`{"v":1,"links":["000000000000000A"]}`)),
		"null links":         resealForTest([]byte(`{"v":1,"links":null}`)),
		"version":            resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
	} {
		if _, err := UnmarshalReportLinks(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
	if empty, err := (ReportLinks{}).MarshalBinary(); err != nil {
		t.Fatal(err)
	} else if back, err := UnmarshalReportLinks(empty); err != nil || len(back.Links) != 0 {
		t.Fatalf("empty links: %+v, %v", back, err)
	}
}

func TestRegistrySealed(t *testing.T) {
	reg, err := NewRegistry(testLookup)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Sealed() {
		t.Fatal("a new registry is sealed")
	}
	reg.Seal()
	if !reg.Sealed() {
		t.Fatal("Seal did not seal")
	}
}

func TestRecordEncodersRejectInvalidValues(t *testing.T) {
	for name, r := range map[string]ReportLinks{
		"invalid ID":           {Links: []string{"bad"}},
		"unsorted":             {Links: []string{"0000000000000002", "0000000000000001"}},
		"duplicate":            {Links: []string{"0000000000000001", "0000000000000001"}},
		"overflow before full": {Dropped: 1},
		"too many":             {Links: []string{"0000000000000001", "0000000000000002", "0000000000000003", "0000000000000004", "0000000000000005", "0000000000000006", "0000000000000007", "0000000000000008", "0000000000000009"}},
	} {
		if _, err := r.MarshalBinary(); refusalReason(err) != ReasonInvalid {
			t.Errorf("%s encoded: %v", name, err)
		}
		if _, _, err := r.Add("ffffffffffffffff"); refusalReason(err) != ReasonInvalid {
			t.Errorf("%s updated: %v", name, err)
		}
	}
	var inv Inventory
	if _, err := inv.MarshalBinary(); refusalReason(err) != ReasonInvalid {
		t.Fatalf("uninitialized inventory encoded: %v", err)
	}
}

func TestUninitializedInventoryCannotMatchGenerations(t *testing.T) {
	g := NewGenerations()
	if (&Inventory{}).MatchesGenerations(g) {
		t.Fatal("uninitialized inventory matches a fresh generation tracker")
	}
	empty, err := NewInventory(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.MatchesGenerations(g) {
		t.Fatal("initialized empty inventory does not match a fresh tracker")
	}
}

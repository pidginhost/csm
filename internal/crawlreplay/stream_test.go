package crawlreplay

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	testSite  = "dom-0a1b2c.example"
	testL2    = "k-00000000000000a2"
	testL1    = "k-00000000000000a1"
	testBind  = "b-00000000000000b1"
	testAcct  = "acct-0a1b2c"
	testEpoch = int64(1790000000)
)

func validRecord() Record {
	return Record{
		T: testEpoch, File: 0, Seq: 1, Site: testSite, Account: testAcct, Binding: testBind,
		L2: testL2, L1: testL1, Class: ClassExpensive, Status: 200, Referer: RefNone,
		Bot: "googlebot", BotRange: true, Label: LabelAttack, Episode: "e1",
	}
}

func TestRecordRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := validRecord()
	if err := WriteRow(&buf, want); err != nil {
		t.Fatal(err)
	}
	var got []Record
	if err := ReadRecords(&buf, func(r Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestRecordValidateRejectsEachField(t *testing.T) {
	for name, mutate := range map[string]func(*Record){
		"t":           func(r *Record) { r.T = 0 },
		"f":           func(r *Record) { r.File = -1 },
		"n":           func(r *Record) { r.Seq = 0 },
		"site raw":    func(r *Record) { r.Site = "example.com" },
		"acct raw":    func(r *Record) { r.Account = "customer" },
		"binding raw": func(r *Record) { r.Binding = "192.0.2.1" },
		"class":       func(r *Record) { r.Class = 3 },
		"l2 missing":  func(r *Record) { r.L2 = "" },
		"l1 missing":  func(r *Record) { r.L1 = "" },
		"l1 raw":      func(r *Record) { r.L1 = "k-filter_color" },
		"l2 on dynamic": func(r *Record) {
			r.Class = ClassDynamic
			r.L1 = ""
		},
		"status":       func(r *Record) { r.Status = 600 },
		"referer":      func(r *Record) { r.Referer = 4 },
		"bot text":     func(r *Record) { r.Bot = "Googlebot/2.1 (+http://www.google.com/bot.html)" },
		"bot range":    func(r *Record) { r.Bot = "" },
		"label":        func(r *Record) { r.Label = "maybe" },
		"episode none": func(r *Record) { r.Episode = "" },
		"episode text": func(r *Record) { r.Episode = "Site A crawl" },
		"healthy episode": func(r *Record) {
			r.Label = LabelHealthy
		},
	} {
		r := validRecord()
		mutate(&r)
		if err := r.Validate(); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: Validate() = %v, want ErrRecord", name, err)
		}
	}
}

func TestVolumeValidate(t *testing.T) {
	good := Volume{Site: testSite, Minute: testEpoch / 60, Lines: 3, Bytes: 300, NoTarget: 1, NoBinding: 3}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Volume){
		"site":       func(v *Volume) { v.Site = "example.com" },
		"minute":     func(v *Volume) { v.Minute = 0 },
		"lines":      func(v *Volume) { v.Lines = 0 },
		"bytes":      func(v *Volume) { v.Bytes = 2 },
		"no_target":  func(v *Volume) { v.NoTarget = 4 },
		"no_binding": func(v *Volume) { v.NoBinding = -1 },
	} {
		v := good
		mutate(&v)
		if err := v.Validate(); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: Validate() = %v, want ErrRecord", name, err)
		}
	}
}

func TestReadRejectsUnknownFieldsWithoutEchoingInput(t *testing.T) {
	in := `{"t":1790000000,"f":0,"n":1,"site":"dom-0a1b2c.example","c":0,"s":200,"r":0,"ip":"203.0.113.9"}`
	err := ReadRecords(strings.NewReader(in), func(Record) error { return nil })
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("err = %v, want ErrDecode", err)
	}
	if strings.Contains(err.Error(), "203.0.113.9") || strings.Contains(err.Error(), "ip") {
		t.Fatalf("error echoes input: %v", err)
	}
}

func TestReadStopsAtInvalidRow(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRow(&buf, validRecord()); err != nil {
		t.Fatal(err)
	}
	buf.WriteString(`{"t":1790000000,"f":0,"n":2,"site":"example.com","c":0,"s":200,"r":0}` + "\n")
	seen := 0
	err := ReadRecords(&buf, func(Record) error { seen++; return nil })
	if !errors.Is(err, ErrRecord) || seen != 1 {
		t.Fatalf("seen=%d err=%v, want one row then ErrRecord", seen, err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error echoes input: %v", err)
	}
}

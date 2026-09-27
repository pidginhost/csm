package crawlreplay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
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
		"bot text":     func(r *Record) { r.Bot = "Googlebot/2.1 (+http://crawler.example/bot.html)" },
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

func TestReadRecordsClosedSchema(t *testing.T) {
	r := validRecord()
	r.Infra = true
	testClosedSchema(t, r, []string{"t", "f", "n", "site", "c", "s", "r"}, ReadRecords)
}

func TestReadVolumeClosedSchema(t *testing.T) {
	v := Volume{Site: testSite, Minute: testEpoch / 60, Lines: 3, Bytes: 300, NoTarget: 1, NoBinding: 3}
	testClosedSchema(t, v, []string{"site", "m", "lines", "bytes", "no_target", "no_binding"}, ReadVolume)
}

func testClosedSchema[T row](t *testing.T, good T, required []string, read func(io.Reader, func(T) error) error) {
	t.Helper()
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, bad string) {
		t.Helper()
		seen := 0
		input := string(raw) + "\n" + bad + "\n" + string(raw)
		err := read(strings.NewReader(input), func(T) error { seen++; return nil })
		if !errors.Is(err, ErrDecode) || seen != 1 {
			t.Fatalf("seen=%d err=%v, want one row then ErrDecode", seen, err)
		}
		if err.Error() != "row 2: "+ErrDecode.Error() {
			t.Fatalf("error carries input or wrong row: %v", err)
		}
	}
	for name, value := range fields {
		key := `"` + name + `":`
		member := key + string(value)
		for kind, bad := range map[string]string{
			"duplicate": string(raw[:len(raw)-1]) + "," + member + "}",
			"escaped duplicate": string(raw[:len(raw)-1]) + `,"\u00` +
				fmt.Sprintf("%02x", name[0]) + name[1:] + `":` + string(value) + "}",
			"case":    strings.Replace(string(raw), key, `"`+strings.ToUpper(name)+`":`, 1),
			"null":    strings.Replace(string(raw), member, key+"null", 1),
			"type":    strings.Replace(string(raw), member, key+"[]", 1),
			"unknown": strings.Replace(string(raw), key, `"private.example":`, 1),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) { reject(t, bad) })
		}
	}
	for _, name := range required {
		t.Run(name+"/missing", func(t *testing.T) {
			value := fields[name]
			delete(fields, name)
			bad, err := json.Marshal(fields)
			fields[name] = value
			if err != nil {
				t.Fatal(err)
			}
			reject(t, string(bad))
		})
	}
	for _, bad := range []string{"null", "[]", "true", "42", `"private.example"`} {
		t.Run("not object/"+bad, func(t *testing.T) { reject(t, bad) })
	}
	// EOF is successful only between objects, never inside one.
	for end := 1; end < len(raw); end++ {
		seen := 0
		err := read(bytes.NewReader(raw[:end]), func(T) error { seen++; return nil })
		if !errors.Is(err, ErrDecode) || seen != 0 {
			t.Fatalf("prefix %d: seen=%d err=%v, want ErrDecode without callback", end, seen, err)
		}
	}
}

func TestReadRecordsOptionalFields(t *testing.T) {
	for _, class := range []uint8{ClassOther, ClassDynamic, ClassExpensive} {
		r := Record{T: testEpoch, File: 0, Seq: 1, Site: testSite, Class: class, Status: 200, Referer: RefNone}
		if class == ClassExpensive {
			r.L1, r.L2 = testL1, testL2
		}
		var buf bytes.Buffer
		if err := WriteRow(&buf, r); err != nil {
			t.Fatal(err)
		}
		seen := 0
		err := ReadRecords(&buf, func(got Record) error {
			seen++
			if got != r {
				t.Errorf("got %+v, want %+v", got, r)
			}
			return nil
		})
		if err != nil || seen != 1 {
			t.Fatalf("class %d: seen=%d err=%v", class, seen, err)
		}
	}
}

func TestReadVolumeRoundTrip(t *testing.T) {
	want := []Volume{
		{Site: testSite, Minute: testEpoch / 60, Lines: 1, Bytes: 1},
		{Site: testSite, Minute: testEpoch/60 + 1, Lines: 3, Bytes: 300, NoTarget: 1, NoBinding: 3},
	}
	var buf bytes.Buffer
	for _, v := range want {
		if err := WriteRow(&buf, v); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	err := ReadVolume(&buf, func(got Volume) error {
		if seen >= len(want) || got != want[seen] {
			t.Fatalf("row %d: unexpected volume %+v", seen, got)
		}
		seen++
		return nil
	})
	if err != nil || seen != len(want) {
		t.Fatalf("seen=%d err=%v, want %d rows", seen, err, len(want))
	}
}

func TestReadRecordsErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRow(&buf, validRecord()); err != nil {
		t.Fatal(err)
	}
	input := buf.String()
	privateErr := errors.New("private.example read failed")
	for _, prefix := range []string{"", input[:len(input)/2], input, input + "\n "} {
		seen := 0
		r := io.MultiReader(strings.NewReader(prefix), iotest.ErrReader(privateErr))
		err := ReadRecords(r, func(Record) error { seen++; return nil })
		wantSeen := 0
		if len(prefix) >= len(input) {
			wantSeen = 1
		}
		if !errors.Is(err, ErrDecode) || seen != wantSeen || strings.Contains(err.Error(), "private.example") {
			t.Fatalf("prefix length %d: seen=%d err=%v", len(prefix), seen, err)
		}
	}
	stop := errors.New("callback stopped")
	seen := 0
	err := ReadRecords(strings.NewReader(input+"invalid"), func(Record) error { seen++; return stop })
	if err != stop || seen != 1 {
		t.Fatalf("callback: seen=%d err=%v, want callback error", seen, err)
	}
}

type streamWriterFunc func([]byte) (int, error)

func (f streamWriterFunc) Write(b []byte) (int, error) { return f(b) }

func TestWriteRowShortWrite(t *testing.T) {
	for _, count := range []int{0, 1} {
		err := WriteRow(streamWriterFunc(func([]byte) (int, error) { return count, nil }), validRecord())
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("wrote %d bytes: err=%v, want io.ErrShortWrite", count, err)
		}
	}
}

func TestWriteRowErrors(t *testing.T) {
	writeErr := errors.New("write failed")
	err := WriteRow(streamWriterFunc(func([]byte) (int, error) { return 1, writeErr }), validRecord())
	if err != writeErr {
		t.Fatalf("err=%v, want writer error", err)
	}
	r := validRecord()
	r.Site = "example.com"
	err = WriteRow(streamWriterFunc(func([]byte) (int, error) {
		t.Fatal("writer called for invalid row")
		return 0, nil
	}), r)
	if !errors.Is(err, ErrRecord) {
		t.Fatalf("err=%v, want ErrRecord", err)
	}
}

package crawlid

import (
	"bytes"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func FuzzParseTarget(f *testing.F) {
	vf := loadVectors(f)
	for _, v := range vf.Targets {
		raw, limit := v.Raw, vf.MaxLen
		if v.RawB64 != "" {
			raw = string(b64(f, v.RawB64))
		}
		if v.MaxLen != 0 {
			limit = v.MaxLen
		}
		f.Add(raw, limit)
	}
	for _, raw := range []string{"", "/", "/?a[0][=1", "/?a]b[0]=1", "/?a[0]][1]=1", "/?a[][[1]]=1", "/a%3Fb?x?y=z=w&&"} {
		for _, limit := range []int{-1, 0, len(raw) - 1, len(raw), len(raw) + 1} {
			f.Add(raw, limit)
		}
	}
	f.Fuzz(func(t *testing.T, raw string, limit int) {
		got, err := ParseTarget(raw, limit)
		var wantErr error
		switch {
		case raw == "":
			wantErr = ErrEmptyTarget
		case len(raw) > limit:
			wantErr = ErrTargetTooLong
		case raw[0] != '/':
			wantErr = ErrNotOriginForm
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("ParseTarget(%q, %d): error = %v, want %v", raw, limit, err, wantErr)
		}
		if err != nil {
			if !reflect.DeepEqual(got, Target{}) {
				t.Fatalf("error returned partial identity: %+v", got)
			}
			return
		}
		for i, name := range got.Names {
			if bytes.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				t.Fatalf("name contains unfolded ASCII: %q", name)
			}
			if i > 0 && bytes.Compare(got.Names[i-1], name) >= 0 {
				t.Fatalf("names are not strictly byte-sorted: %q", got.Names)
			}
		}
		p, q, _ := strings.Cut(raw, "?")
		if got.HasQuery != (q != "") {
			t.Fatalf("HasQuery = %v for query %q", got.HasQuery, q)
		}
		if q == "" {
			if len(got.Names) != 0 {
				t.Fatalf("queryless target has names: %q", got.Names)
			}
			return
		}

		// Values, field order and repeated fields cannot change an identity.
		fields := strings.Split(q, "&")
		for i, field := range fields {
			if field != "" {
				name, _, _ := strings.Cut(field, "=")
				fields[i] = name + "=%FF%26ignored=1+%zz"
			}
		}
		slices.Reverse(fields)
		fields = append(fields, fields...)
		changed := p + "?" + strings.Join(fields, "&")
		again, err := ParseTarget(changed, len(changed))
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("changing values/order/duplicates changed identity: %+v -> %+v, err %v", got, again, err)
		}
	})
}

func FuzzTargetEncodedBytes(f *testing.F) {
	for _, seed := range [][2]string{
		{"", ""}, {"A+%2F/?;", "A+%26&=;"}, {"\x00\xff", "\xfe\x00Z"},
		{"..", "A[0][X][]"}, {".", "A[X][001]"}, {"/", "A[0]["},
		{"x", "A]B[0]"}, {"x", "A[0]][1]"}, {"x", "A[][[1]]"},
		{"\xc3\x84", "\xc3\x84[-1][+1][\xd9\xa1][00]"},
	} {
		f.Add(seed[0], seed[1])
	}
	// Use the standard encoder and a whole-name grammar as independent oracles.
	chain := regexp.MustCompile(`^[^\[\]]+(\[[^\[\]]*\])+$`)
	numeric := regexp.MustCompile(`\[[0-9]*\]`)
	escapes := regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	var folds []string
	for _, upper := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		folds = append(folds, string(upper), strings.ToLower(string(upper)))
	}
	lower := strings.NewReplacer(folds...)
	f.Fuzz(func(t *testing.T, segment, name string) {
		raw := "/" + url.PathEscape(segment) + "/tail?" + url.QueryEscape(name) + "=%zz%26ignored=1"
		wantName := lower.Replace(name)
		if chain.MatchString(wantName) {
			wantName = numeric.ReplaceAllLiteralString(wantName, "[]")
		}
		for _, encoded := range []string{raw, escapes.ReplaceAllStringFunc(raw, strings.ToLower)} {
			got, err := ParseTarget(encoded, len(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Segment, []byte(segment)) || !got.HasQuery || got.Ext != "" ||
				len(got.Names) != 1 || !bytes.Equal(got.Names[0], []byte(wantName)) {
				t.Fatalf("encoded bytes: got %+v, want segment %q and name %q", got, segment, wantName)
			}
		}
	})
}

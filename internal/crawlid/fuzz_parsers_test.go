package crawlid

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// supportedForm restates the accepted target forms independently of
// SplitTarget: origin-form, or an http(s) absolute form whose remainder after
// an optional authority is empty or starts a path or query.
var supportedForm = regexp.MustCompile(`(?s)^(/.*|[hH][tT][tT][pP][sS]?:(//[^/?]*)?([/?].*)?)$`)

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
		case !supportedForm.MatchString(raw):
			wantErr = ErrUnsupportedForm
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

func FuzzDecodeKey(f *testing.F) {
	for _, v := range loadVectors(f).Keys {
		f.Add(b64(f, v.EncodedB64))
	}
	f.Add([]byte{})
	f.Add([]byte{'c', 'k', 1, 3, 1, 's'})
	f.Add([]byte{'c', 'k', 1, 1, 1, 's', 0, 1, 0})
	f.Add([]byte{'c', 'k', 1, 3, 0x81, 0, 's'})
	f.Add([]byte{'c', 'k', 1, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})
	f.Add([]byte{'c', 'k', 1, 3, 0x80, 0})
	f.Add([]byte{'c', 'k', 1, 1, 0, 0, 2, 1, 'b', 1, 'a'})
	f.Add([]byte{'c', 'k', 1, 1, 0, 0, 2, 0, 0})
	f.Add([]byte{'c', 'k', 1, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2})
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := DecodeKey(raw)
		if err != nil {
			if !errors.Is(err, ErrBadKey) || !reflect.DeepEqual(got, Key{}) {
				t.Fatalf("invalid key returned %+v, %v", got, err)
			}
			return
		}
		if got.Level < L1 || got.Level > L3 || !bytes.Equal(got.Encode(), raw) {
			t.Fatalf("accepted noncanonical key %x: %+v", raw, got)
		}
		for i := 1; i < len(got.Names); i++ {
			if bytes.Compare(got.Names[i-1], got.Names[i]) >= 0 {
				t.Fatalf("accepted unordered or duplicate names: %q", got.Names)
			}
		}
	})
}

func FuzzKeysForRoundTrip(f *testing.F) {
	for _, v := range loadVectors(f).Targets {
		raw := v.Raw
		if v.RawB64 != "" {
			raw = string(b64(f, v.RawB64))
		}
		f.Add([]byte("example.com"), v.Method, raw)
	}
	f.Fuzz(func(t *testing.T, site []byte, method, raw string) {
		target, err := ParseTarget(raw, len(raw))
		if err != nil {
			return
		}
		class := Classify(method, target)
		keys := KeysFor(site, class, target)
		if !class.Dynamic {
			if keys != nil {
				t.Fatalf("non-dynamic request returned keys: %+v", keys)
			}
			return
		}
		levels := []Level{L3}
		if class.Expensive {
			levels = append(levels, L2, L1)
		}
		if len(keys) != len(levels) {
			t.Fatalf("got %d keys, want levels %v", len(keys), levels)
		}
		for i, key := range keys {
			var segment []byte
			var names [][]byte
			if levels[i] != L3 {
				segment = target.Segment
			}
			if levels[i] == L1 {
				names = target.Names
			}
			decoded, err := DecodeKey(key.Encode())
			if err != nil {
				t.Fatalf("DecodeKey at level %d: %v", levels[i], err)
			}
			for _, got := range []Key{key, decoded} {
				if got.Level != levels[i] || !bytes.Equal(got.Site, site) ||
					!bytes.Equal(got.Segment, segment) || !slices.EqualFunc(got.Names, names, bytes.Equal) {
					t.Fatalf("wrong fields at level %d: %+v", levels[i], got)
				}
			}
		}
	})
}

func FuzzBindingOf(f *testing.F) {
	for _, v := range loadVectors(f).Bindings {
		f.Add(v.IP)
	}
	for _, raw := range []string{
		"192.0.2.10", "::ffff:192.0.2.10", "2001:db8:1:2::3", "2001:db8::1%test0", "192.0.2.10:80", "",
		"2001:db8:abcd:ef01:2345:6789:abcd:ef01", "2001:0DB8:0001:0002:0000:0000:0000:0001",
		"[192.0.2.10]", "[2001:db8::1]:80", "[::ffff:192.0.2.10]:80",
		"192.0.2.10%test0", "2001:db8::1%", "::ffff:192.0.2.10%test0", "::ffff:c000:20a%test0",
		"192.0.2.10/32", "2001:db8::1/64", "::ffff:192.0.002.10",
		"192.0.2.10 ", "\t192.0.2.10", " 2001:db8::1", "2001:db8::1\r\n",
		"192.0.2.10\x00", "2001:db8::1\x00", "\xff",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		binding, ok := BindingOf(raw)
		// A round trip alone also passes for rejected valid inputs and collisions.
		parsed := net.ParseIP(raw)
		if ok != (parsed != nil) {
			t.Fatalf("BindingOf(%q) ok = %v, want %v", raw, ok, parsed != nil)
		}
		if !ok {
			if binding != "" {
				t.Fatal("invalid address returned a partial binding")
			}
			return
		}
		wire := binding.String()
		encoded, err := base64.RawURLEncoding.DecodeString(wire)
		if err != nil || string(encoded) != string(binding) || base64.RawURLEncoding.EncodeToString(encoded) != wire {
			t.Fatal("binding JSON encoding is not canonical or changed the bytes")
		}
		var restored string
		switch {
		case len(binding) == 5 && binding[0] == '4':
			if !bytes.Equal([]byte(binding[1:]), parsed.To4()) {
				t.Fatalf("BindingOf(%q) = %x, want the full IPv4 address", raw, []byte(binding))
			}
			var addr [4]byte
			copy(addr[:], binding[1:])
			restored = netip.AddrFrom4(addr).String()
		case len(binding) == 9 && binding[0] == '6':
			if parsed.To4() != nil || !bytes.Equal([]byte(binding[1:]), parsed[:8]) {
				t.Fatalf("BindingOf(%q) = %x, want the IPv6 /64", raw, []byte(binding))
			}
			var addr [16]byte
			copy(addr[:8], binding[1:])
			restored = netip.AddrFrom16(addr).String()
		default:
			t.Fatalf("bad binding shape %x", []byte(binding))
		}
		again, valid := BindingOf(restored)
		if !valid || binding != again {
			t.Fatal("canonical binding changed on round trip")
		}
	})
}

package crawlid

import "testing"

func TestBindingVectors(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Bindings) == 0 {
		t.Fatal("no binding vectors")
	}
	for _, v := range vf.Bindings {
		b, ok := BindingOf(v.IP)
		if ok != v.OK {
			t.Errorf("BindingOf(%q) ok = %v, want %v", v.IP, ok, v.OK)
			continue
		}
		if !ok && b != "" {
			t.Fatalf("invalid binding returned bytes for %q", v.IP)
		}
		if ok && string(b) != string(b64(t, v.B64)) {
			t.Errorf("BindingOf(%q) bytes = %x, want %x", v.IP, []byte(b), b64(t, v.B64))
		}
		if ok && b.String() != v.B64 {
			t.Errorf("BindingOf(%q) = %s, want %s", v.IP, b.String(), v.B64)
		}
	}
}

func TestBindingSharesOnlyWithinSlash64(t *testing.T) {
	a, aOK := BindingOf("2001:db8:1:2::1")
	b, bOK := BindingOf("2001:db8:1:2:ffff::9")
	c, cOK := BindingOf("2001:db8:1:3::1")
	if !aOK || !bOK || !cOK {
		t.Fatal("valid IPv6 binding rejected")
	}
	if a != b {
		t.Error("same /64 must share a binding")
	}
	if a == c {
		t.Error("different /64 must not share a binding")
	}
	v4, v4OK := BindingOf("192.0.2.10")
	other, otherOK := BindingOf("192.0.2.11")
	if !v4OK || !otherOK {
		t.Fatal("valid IPv4 binding rejected")
	}
	if v4 == other {
		t.Error("IPv4 binds the full address")
	}
}

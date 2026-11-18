package ipmap

import (
	"slices"
	"strings"
	"testing"
)

func TestStalwartNamespaceNames(t *testing.T) {
	for _, c := range []struct {
		s    Symbol
		v6   bool
		want string
	}{
		{Drop, false, "csm-ip-drop"},
		{MailAuth, true, "csm-ip6-mail-auth"},
		{Canary, false, "csm-ip-canary"},
	} {
		if got := StalwartNamespace(c.s, c.v6); got != c.want {
			t.Errorf("StalwartNamespace(%s, %v) = %q, want %q", c.s.Name, c.v6, got, c.want)
		}
	}
	all := StalwartNamespaces()
	if len(all) != 14 {
		t.Fatalf("StalwartNamespaces() has %d names, want 14: %v", len(all), all)
	}
	if all[0] != "csm-ip-drop" || all[1] != "csm-ip6-drop" || all[13] != "csm-ip6-canary" {
		t.Errorf("namespaces not v4 then v6 per symbol in rule order: %v", all)
	}
}

// checkKeys compares the namespaces in want and requires every other
// namespace to be present and empty, apart from the canary's.
func checkKeys(t *testing.T, got map[string][]string, want map[string][]string) {
	t.Helper()
	if len(got) != 14 {
		t.Errorf("got %d namespaces, want 14", len(got))
	}
	for _, ns := range StalwartNamespaces() {
		keys, ok := got[ns]
		if !ok {
			t.Errorf("namespace %s missing", ns)
			continue
		}
		w, listed := want[ns]
		if !listed {
			if ns == "csm-ip-canary" {
				w = []string{CanaryAddr}
			} else {
				w = []string{}
			}
		}
		if !slices.Equal(keys, w) {
			t.Errorf("%s = %v, want %v", ns, keys, w)
		}
	}
}

func TestStalwartKeysIPv4(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Blocked.Name: {"203.0.113.9"},
		Drop.Name:    {"198.18.0.0/15"},
		CINS.Name:    {"198.51.100.0/22", "192.0.2.128/30"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip-blocked": {"203.0.113.9"},
		"csm-ip-drop":    {"198.18.*", "198.19.*"},
		"csm-ip-cins":    {"192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131", "198.51.100.*", "198.51.101.*", "198.51.102.*", "198.51.103.*"},
		"csm-ip-canary":  {"192.0.2.255"},
	})
}

func TestStalwartKeysIPv6(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Spam.Name:     {"2001:db8:0:5::/64", "2001:db8::9"},
		MailAuth.Name: {"2001:db8:1::/63"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip6-spam": {
			"*.5.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		},
		"csm-ip6-mail-auth": {
			"*.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2",
			"*.1.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2",
		},
	})
}

// An IPv4-mapped network must land in the IPv4 namespace as IPv4 text,
// the form Stalwart compares remote_ip against.
func TestStalwartKeysMappedPrefix(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Drop.Name: {"::ffff:198.51.100.0/120"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip-drop": {"198.51.100.*"},
	})
}

func TestStalwartKeysNestedStronger(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		CINS.Name: {"198.51.100.0/24"},
		Drop.Name: {"198.51.100.7"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip-cins": {"198.51.100.*"},
		"csm-ip-drop": {"198.51.100.7"},
	})
}

func TestStalwartKeysWidestExpansion(t *testing.T) {
	m := Build(Sources{Entries: map[string][]string{
		Drop.Name: {"203.0.0.0/9", "2001:db8:0:8::/61"},
	}})
	keys := m.StalwartKeys()
	v4 := keys["csm-ip-drop"]
	if len(v4) != 128 {
		t.Fatalf("/9 gave %d keys, want 128", len(v4))
	}
	for i, k := range v4 {
		if !strings.HasPrefix(k, "203.") || !strings.HasSuffix(k, ".*") || strings.Count(k, ".") != 2 {
			t.Fatalf("/9 key %d = %q, want 203.b.*", i, k)
		}
	}
	if v4[0] != "203.0.*" || !slices.Contains(v4, "203.127.*") || slices.Contains(v4, "203.128.*") {
		t.Errorf("/9 keys do not cover 203.0 to 203.127: first %q", v4[0])
	}
	v6 := keys["csm-ip6-drop"]
	if len(v6) != 8 {
		t.Fatalf("/61 gave %d keys, want 8: %v", len(v6), v6)
	}
	if v6[0] != "*.8.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2" || v6[7] != "*.f.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2" {
		t.Errorf("/61 keys = %v", v6)
	}
}

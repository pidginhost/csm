package ipmap

import (
	"slices"
	"strconv"
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
	want := []string{
		"csm-ip-drop", "csm-ip6-drop",
		"csm-ip-blocked", "csm-ip6-blocked",
		"csm-ip-mail-auth", "csm-ip6-mail-auth",
		"csm-ip-spam", "csm-ip6-spam",
		"csm-ip-blocklistde", "csm-ip6-blocklistde",
		"csm-ip-cins", "csm-ip6-cins",
		"csm-ip-canary", "csm-ip6-canary",
	}
	if !slices.Equal(all, want) {
		t.Errorf("StalwartNamespaces() = %v, want %v", all, want)
	}
}

// checkKeys requires all namespaces, with only the expected keys and the canary.
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
		CINS.Name:    {"192.0.2.128/30"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip-blocked": {"203.0.113.9"},
		"csm-ip-drop":    {"198.18.*", "198.19.*"},
		"csm-ip-cins":    {"192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131"},
		"csm-ip-canary":  {"192.0.2.255"},
	})
	// Keep the /22 separate so the stronger /15 does not suppress its keys.
	m = Build(Sources{Entries: map[string][]string{
		CINS.Name: {"198.18.100.0/22"},
	}})
	checkKeys(t, m.StalwartKeys(), map[string][]string{
		"csm-ip-cins": {"198.18.100.*", "198.18.101.*", "198.18.102.*", "198.18.103.*"},
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

func TestStalwartKeysIPv6HostBoundary(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   []string
	}{
		{"2001:db8::/124", []string{
			"*.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		}},
		{"2001:db8::8/125", []string{
			"8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"e.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		}},
		{"2001:db8::8/126", []string{
			"8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		}},
		{"2001:db8::8/127", []string{
			"8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
			"9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		}},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			m := Build(Sources{Entries: map[string][]string{
				Drop.Name: {tc.prefix},
			}})
			checkKeys(t, m.StalwartKeys(), map[string][]string{
				"csm-ip6-drop": tc.want,
			})
		})
	}
}

// IPv4-mapped networks must use the IPv4 namespace and dotted text for remote_ip.
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
		Drop.Name:    {"198.18.0.0/17", "2001:db8:0:8::/61"},
		Blocked.Name: {"192.0.2.0/25"},
	}})
	keys := m.StalwartKeys()
	var globs []string
	for n := range 128 {
		globs = append(globs, "198.18."+strconv.Itoa(n)+".*")
	}
	slices.Sort(globs)
	if v4 := keys["csm-ip-drop"]; !slices.Equal(v4, globs) {
		t.Errorf("/17 gave %d keys, want 198.18.N.* for N 0..127: %v", len(v4), v4)
	}
	var exact []string
	for n := range 128 {
		exact = append(exact, "192.0.2."+strconv.Itoa(n))
	}
	slices.Sort(exact)
	if v4 := keys["csm-ip-blocked"]; !slices.Equal(v4, exact) {
		t.Errorf("/25 gave %d keys, want 192.0.2.0 to 192.0.2.127 with no glob: %v", len(v4), v4)
	}
	v6 := keys["csm-ip6-drop"]
	want := []string{
		"*.8.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.9.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.a.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.b.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.c.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.d.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.e.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		"*.f.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
	}
	if !slices.Equal(v6, want) {
		t.Errorf("/61 keys = %v, want %v", v6, want)
	}
}

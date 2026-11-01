package sharedsenders

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzLoadCache feeds arbitrary bytes to the cache parser. An accepted cache
// must hold only table providers within the limits, and must load again
// unchanged after Refresh's encoder writes it back.
func FuzzLoadCache(f *testing.F) {
	valid, err := json.Marshal(validCache())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(bytes.Replace(valid, []byte("mail.example.net"), []byte("Mail.Example.NET"), 1))
	f.Add(bytes.Replace(valid, []byte("198.51.100.0/24"), []byte("198.51.100.0/33"), 1))
	f.Add(bytes.Replace(valid, []byte("198.51.100.0/24"), []byte("::ffff:198.51.100.0/120"), 1))
	f.Add(append(bytes.Clone(valid), bytes.Repeat([]byte(" "), maxCacheBytes)...))
	f.Add([]byte(`{"version":1,"providers":{"google":null}}`))
	f.Add([]byte(`{"version":1,"providers":{"other":{"root":"x","nets":["bad"]}}}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`null`))
	f.Add([]byte("{\"version\":1,\"providers\":{\"yahoo\":{\"ptr\":[\"\xff\"]}}}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := parseCache(data)
		if err != nil {
			return
		}
		for name, p := range s {
			if p.cache.Root != providers[name] || providers[name] == "" {
				t.Fatalf("accepted provider %q with root %q", name, p.cache.Root)
			}
			if len(p.nets) != len(p.cache.Nets) || len(p.nets) > maxNets || len(p.cache.PTR) > maxPTRDomains {
				t.Fatalf("accepted %s with %d prefixes (%d parsed) and %d ptr domains", name, len(p.cache.Nets), len(p.nets), len(p.cache.PTR))
			}
			for _, n := range p.nets {
				if n != n.Masked() || n.Addr().Is4In6() {
					t.Fatalf("accepted %s prefix %v", name, n)
				}
			}
			for _, d := range p.cache.PTR {
				if !validPTRDomain(d) {
					t.Fatalf("accepted %s ptr domain %q", name, d)
				}
			}
		}
		again, err := encodeCache(s)
		if err != nil {
			// Fields the input left out can push a cache near the limit over it.
			return
		}
		s2, err := parseCache(again)
		if err != nil {
			t.Fatalf("re-encoded cache does not load: %v", err)
		}
		if !reflect.DeepEqual(s, s2) {
			t.Fatalf("re-encoded cache loads as %+v, want %+v", s2, s)
		}
	})
}

// FuzzPTRMatch checks that a reverse name matches a ptr domain only when it
// is that domain or a name under it, compared in ASCII without case and
// without the root dot.
func FuzzPTRMatch(f *testing.F) {
	for _, seed := range [][2]string{
		{"mx1.mail.example.net.", "mail.example.net"},
		{"MX1.Mail.Example.NET.", "mail.example.net"},
		{"mail.example.net", "mail.example.net"},
		{"notmail.example.net.", "mail.example.net"},
		{"mail.example.net.example.org.", "mail.example.net"},
		{"mail.example.net..", "mail.example.net"},
		{"", "mail.example.net"},
		{".", "mail.example.net"},
		{"\u212a.example", "k.example"},
		{"\xff.mail.example.net", "mail.example.net"},
		{strings.Repeat("a.", 300) + "mail.example.net.", "mail.example.net"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, name, domain string) {
		if !validPTRDomain(domain) {
			return
		}
		host, ok := ptrHost(name, []string{domain})
		if ok {
			for i := 0; i < len(name); i++ {
				if name[i] >= utf8.RuneSelf {
					t.Fatalf("ptrHost(%q, %q) matched a name with non-ASCII bytes", name, domain)
				}
			}
			if host != domain && !strings.HasSuffix(host, "."+domain) {
				t.Fatalf("ptrHost(%q, %q) matched as %q", name, domain, host)
			}
			if !strings.EqualFold(strings.TrimSuffix(name, "."), host) {
				t.Fatalf("ptrHost(%q, %q) returned %q, not the name", name, domain, host)
			}
			for i := 0; i < len(host); i++ {
				if c := host[i]; c >= utf8.RuneSelf || (c >= 'A' && c <= 'Z') {
					t.Fatalf("ptrHost(%q, %q) returned %q, not lower-case ASCII", name, domain, host)
				}
			}
		} else if host != "" {
			t.Fatalf("ptrHost(%q, %q) returned %q without a match", name, domain, host)
		}
		upper := []byte(name)
		for i, c := range upper {
			if c >= 'a' && c <= 'z' {
				upper[i] = c - 'a' + 'A'
			}
		}
		if h, o := ptrHost(string(upper), []string{domain}); h != host || o != ok {
			t.Fatalf("ptrHost(%q) = %q %v, but ptrHost(%q) = %q %v", upper, h, o, name, host, ok)
		}
		if !strings.HasSuffix(name, ".") {
			if h, o := ptrHost(name+".", []string{domain}); h != host || o != ok {
				t.Fatalf("ptrHost(%q) = %q %v, but ptrHost(%q) = %q %v", name+".", h, o, name, host, ok)
			}
		}
	})
}

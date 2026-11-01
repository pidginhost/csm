package mailranges

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestStrictSPFBoundsRepeatedIncludes(t *testing.T) {
	allowDocumentationPrefixes(t)
	r := mapResolver{"d5.example.com": {"v=spf1 ip4:198.51.100.7 -all"}}
	for i := 0; i < 5; i++ {
		r[fmt.Sprintf("d%d.example.com", i)] = []string{
			"v=spf1" + strings.Repeat(fmt.Sprintf(" include:d%d.example.com", i+1), 8) + " -all",
		}
	}
	st := &spfResolveState{strict: true, onPath: make(map[string]bool), memo: make(map[string][]*net.IPNet)}
	if _, err := resolveSPFRec(context.Background(), r, "d0.example.com", st, 0); err != nil {
		t.Fatal(err)
	}
	if st.lookups != 6 {
		t.Fatalf("lookups = %d, want 6", st.lookups)
	}
	for domain, nets := range st.memo {
		if len(nets) != 1 || nets[0].String() != "198.51.100.7/32" {
			t.Errorf("%s retained %d prefixes for one sender", domain, len(nets))
		}
	}
}

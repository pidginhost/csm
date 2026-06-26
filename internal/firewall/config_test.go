package firewall

import "testing"

func TestExemptKnownMailProviders_DefaultsTrueWhenNil(t *testing.T) {
	c := &FirewallConfig{}
	if !c.ExemptKnownMailProviders() {
		t.Fatal("nil pointer must default to true")
	}
	f := false
	c.DOSExemptKnownMailProviders = &f
	if c.ExemptKnownMailProviders() {
		t.Fatal("explicit false must stay false")
	}
}

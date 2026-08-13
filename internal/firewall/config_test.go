package firewall

import (
	"reflect"
	"testing"
)

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

func TestMergeInfraIPsDeduplicatesEquivalentEntries(t *testing.T) {
	got := MergeInfraIPs(
		[]string{" 203.0.113.5 ", "2001:0db8:0:0::1", "Panel.EXAMPLE.", ""},
		[]string{"203.0.113.5/32", "2001:db8::1/128", "panel.example", "198.51.100.0/24"},
	)
	want := []string{"203.0.113.5", "2001:0db8:0:0::1", "Panel.EXAMPLE.", "198.51.100.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeInfraIPs() = %v, want %v", got, want)
	}
}

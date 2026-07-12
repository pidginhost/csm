package firewall

import (
	"reflect"
	"testing"
)

func TestEffectiveIPv6PortsUseExplicitListOrIPv4Fallback(t *testing.T) {
	if got := effectiveIPv6Ports([]int{25, 443}, []int{587}); !reflect.DeepEqual(got, []int{587}) {
		t.Fatalf("explicit IPv6 ports = %v, want [587]", got)
	}
	if got := effectiveIPv6Ports([]int{25, 443}, nil); !reflect.DeepEqual(got, []int{25, 443}) {
		t.Fatalf("fallback IPv6 ports = %v, want IPv4 list", got)
	}
}

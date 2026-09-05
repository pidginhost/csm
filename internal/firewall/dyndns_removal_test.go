package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type retryRemovalEngine struct {
	mockEngine
	fail bool
}

func (e *retryRemovalEngine) RemoveAllowIPBySource(ip, source string) error {
	e.removed = append(e.removed, ip)
	if e.fail {
		return errors.New("persist denied")
	}
	return nil
}

func TestDynDNSRetriesFailedRemoval(t *testing.T) {
	e := &retryRemovalEngine{fail: true}
	d := NewDynDNSResolver([]string{"panel.example.net"}, e)
	d.resolved["panel.example.net"] = []string{"192.0.2.10"}
	d.lookupFn = func(context.Context, string) ([]string, error) { return []string{"192.0.2.11"}, nil }
	d.tickOnce(context.Background())
	e.fail = false
	d.tickOnce(context.Background())
	d.tickOnce(context.Background())
	if !reflect.DeepEqual(e.removed, []string{"192.0.2.10", "192.0.2.10"}) {
		t.Errorf("removals = %v, want failed removal retried exactly once", e.removed)
	}
	if !reflect.DeepEqual(e.allowed, []string{"192.0.2.11"}) {
		t.Errorf("adds = %v, want one successful new allow", e.allowed)
	}
	if !reflect.DeepEqual(d.resolved["panel.example.net"], []string{"192.0.2.11"}) {
		t.Errorf("tracked IPs = %v", d.resolved)
	}
}

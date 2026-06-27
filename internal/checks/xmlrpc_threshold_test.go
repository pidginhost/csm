package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// TestEmitLegacyXMLRPCThresholdConfigurable verifies xmlrpc_abuse honors the
// operator-tunable thresholds.xmlrpc_threshold: it fires at or above the
// threshold, stays silent below it, and is fully disabled at 0 (so legitimate
// Jetpack/WooCommerce sites are not hard-blocked).
func TestEmitLegacyXMLRPCThresholdConfigurable(t *testing.T) {
	build := func(n int) *domlogStats {
		s := newDomlogStats()
		rec := accessLogRecord{RemoteIP: "203.0.113.7", Method: "POST", URI: "/xmlrpc.php"}
		for i := 0; i < n; i++ {
			s.scan(rec, nil, nopBotClassifier{})
		}
		return s
	}
	cfgWith := func(thr int) *config.Config {
		c := &config.Config{}
		c.Thresholds.XMLRPCThreshold = thr
		return c
	}
	hasXMLRPC := func(fs []alert.Finding) bool {
		for _, f := range fs {
			if f.Check == "xmlrpc_abuse" {
				return true
			}
		}
		return false
	}

	if !hasXMLRPC(build(60).emitLegacy(cfgWith(50))) {
		t.Error("60 requests >= threshold 50 should emit xmlrpc_abuse")
	}
	if hasXMLRPC(build(40).emitLegacy(cfgWith(50))) {
		t.Error("40 requests < threshold 50 must not emit xmlrpc_abuse")
	}
	if hasXMLRPC(build(500).emitLegacy(cfgWith(0))) {
		t.Error("threshold 0 must disable xmlrpc_abuse even at high request counts")
	}
}

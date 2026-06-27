package config

import "testing"

// TestConfig_XMLRPCThresholdDefaultsAndZeroDisables checks the presence-gated
// xmlrpc_threshold: absent -> default, explicit 0 -> disabled, explicit value
// preserved.
func TestConfig_XMLRPCThresholdDefaultsAndZeroDisables(t *testing.T) {
	// Absent key -> default.
	cfg, err := LoadBytes([]byte("hostname: \"\"\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.XMLRPCThreshold != DefaultXMLRPCThreshold {
		t.Errorf("default XMLRPCThreshold = %d, want %d", cfg.Thresholds.XMLRPCThreshold, DefaultXMLRPCThreshold)
	}

	// Explicit 0 -> disabled (presence prevents the default from re-applying).
	cfg, err = LoadBytes([]byte("thresholds:\n  xmlrpc_threshold: 0\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.XMLRPCThreshold != 0 {
		t.Errorf("explicit 0 XMLRPCThreshold = %d, want 0", cfg.Thresholds.XMLRPCThreshold)
	}

	// Explicit value preserved.
	cfg, err = LoadBytes([]byte("thresholds:\n  xmlrpc_threshold: 50\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Thresholds.XMLRPCThreshold != 50 {
		t.Errorf("explicit XMLRPCThreshold = %d, want 50", cfg.Thresholds.XMLRPCThreshold)
	}
}

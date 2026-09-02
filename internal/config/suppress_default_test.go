package config

import "testing"

// suppress_webmail_alerts is documented and shipped as true in both YAML
// templates, but the code default was the zero value: a config written
// before the key existed, or one that simply omits it, alerted on every
// webmail login. Absent means true; an explicit false is kept.
func TestSuppressWebmailDefaultsTrueWhenAbsent(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Suppressions.SuppressWebmail {
		t.Fatal("suppress_webmail_alerts absent should default to true")
	}
}

func TestSuppressWebmailExplicitFalseKept(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\nsuppressions:\n  suppress_webmail_alerts: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Suppressions.SuppressWebmail {
		t.Fatal("explicit suppress_webmail_alerts: false was overridden by the default")
	}
}

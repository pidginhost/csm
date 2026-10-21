package config

import (
	"strings"
	"testing"
)

type reportTarget = struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	Transport string `yaml:"transport"`
	NodeID    string `yaml:"node_id"`
	KeyID     string `yaml:"key_id"`
	KeyEnv    string `yaml:"key_env"`
	TokenEnv  string `yaml:"token_env"`
}

func authTargetConfig(setURL string, targets ...reportTarget) *Config {
	cfg := lockoutTestConfig(nil)
	cfg.Reputation.Central.Enabled = true
	cfg.Reputation.Central.SetURL = setURL
	cfg.Reputation.Central.AuthTarget = "central"
	cfg.Reputation.Report.Targets = targets
	return cfg
}

func centralTarget() reportTarget {
	return reportTarget{Name: "central", URL: "https://abuse.example.net/report", Transport: "ed25519",
		NodeID: "n_000000000000000000000001", KeyID: "k_000000000000000000000002", KeyEnv: "CSM_REPORT_KEY"}
}

func TestValidateCentralAuthTarget(t *testing.T) {
	const field = "reputation.central.auth_target"
	const setURL = "https://abuse.example.net/decisions"
	with := func(edit func(*reportTarget)) reportTarget {
		tg := centralTarget()
		edit(&tg)
		return tg
	}
	for _, c := range []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"valid", authTargetConfig(setURL, centralTarget()), ""},
		{"explicit default port", authTargetConfig("https://abuse.example.net:443/decisions", centralTarget()), ""},
		{"host case", authTargetConfig("https://ABUSE.example.net/decisions", centralTarget()), ""},
		{"no such target", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.Name = "other" })), "exactly one"},
		{"two targets", authTargetConfig(setURL, centralTarget(), centralTarget()), "exactly one"},
		{"hmac target", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.Transport = "hmac" })), "ed25519"},
		{"no node_id", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.NodeID = "" })), "node_id"},
		{"no key_id", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.KeyID = "" })), "key_id"},
		{"no key_env", authTargetConfig(setURL, with(func(tg *reportTarget) { tg.KeyEnv = "" })), "key_env"},
		{"other host", authTargetConfig("https://lists.example.net/decisions", centralTarget()), "same scheme, host and port"},
		{"other port", authTargetConfig("https://abuse.example.net:8443/decisions", centralTarget()), "same scheme, host and port"},
		{"other scheme", authTargetConfig("http://abuse.example.net/decisions", centralTarget()), "same scheme, host and port"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, ok := findResult(Validate(c.cfg), "error", field)
			if c.wantErr == "" && ok {
				t.Fatalf("unexpected error: %s", res.Message)
			}
			if c.wantErr != "" && (!ok || !strings.Contains(res.Message, c.wantErr)) {
				t.Fatalf("error = %q (found %v), want it to mention %q", res.Message, ok, c.wantErr)
			}
		})
	}
	unset := authTargetConfig(setURL)
	unset.Reputation.Central.AuthTarget = ""
	if _, ok := findResult(Validate(unset), "error", field); ok {
		t.Fatal("an unset auth_target must stay valid: pulls stay unsigned")
	}
}

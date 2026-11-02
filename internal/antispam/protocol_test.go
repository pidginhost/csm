package antispam

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestApplyRequestRoundTrip(t *testing.T) {
	want := Settings{DryRun: true, Socket: DefaultSocket, RejectScore: 20, TagScore: 8}
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"operation":"apply","enabled":true,"dry_run":true,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":20,"tag_score":8}` {
		t.Fatalf("wire form = %s", data)
	}
	req, got, err := DecodeRequest(data)
	if err != nil || req.Operation != OpApply || !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeRequest = %+v, %+v, %v", req, got, err)
	}
}

func TestRemoveRequestRoundTrip(t *testing.T) {
	data, err := json.Marshal(RemoveRequest())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"operation":"remove"}` {
		t.Fatalf("wire form = %s", data)
	}
	req, s, err := DecodeRequest(data)
	if err != nil || req.Operation != OpRemove || !reflect.DeepEqual(s, Settings{}) {
		t.Fatalf("DecodeRequest = %+v, %+v, %v", req, s, err)
	}
}

const validApply = `{"operation":"apply","enabled":true,"dry_run":false,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6}`

func TestDecodeRequestRejects(t *testing.T) {
	for name, body := range map[string]string{
		"empty":                  ``,
		"null":                   `null`,
		"array":                  `[]`,
		"string":                 `"apply"`,
		"no operation":           `{}`,
		"unknown operation":      `{"operation":"restart"}`,
		"unknown field":          `{"operation":"remove","path":"/etc/exim.conf"}`,
		"case variant key":       `{"Operation":"remove"}`,
		"duplicate key":          `{"operation":"remove","operation":"apply"}`,
		"nested object":          `{"operation":{"x":1}}`,
		"nested array":           strings.Replace(validApply, `"tag_score":6`, `"tag_score":[6]`, 1),
		"trailing object":        validApply + `{}`,
		"trailing junk":          validApply + `x`,
		"remove with settings":   `{"operation":"remove","enabled":true}`,
		"remove with null field": `{"operation":"remove","dry_run":null}`,
		"apply missing field":    strings.Replace(validApply, `,"tag_score":6`, ``, 1),
		"apply null field":       strings.Replace(validApply, `"dry_run":false`, `"dry_run":null`, 1),
		"apply disabled":         strings.Replace(validApply, `"enabled":true`, `"enabled":false`, 1),
		"apply fractional score": strings.Replace(validApply, `"reject_score":15`, `"reject_score":15.5`, 1),
		"apply string score":     strings.Replace(validApply, `"reject_score":15`, `"reject_score":"15"`, 1),
		"apply bad socket":       strings.Replace(validApply, `/run/rspamd/csm-normal.sock`, `/run/x.sock variant=x`, 1),
		"apply bad scores":       strings.Replace(validApply, `"tag_score":6`, `"tag_score":15`, 1),
		"oversized":              `{"operation":"remove"}` + strings.Repeat(" ", MaxRequestBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if req, s, err := DecodeRequest([]byte(body)); err == nil {
				t.Fatalf("accepted: %+v %+v", req, s)
			}
		})
	}
}

// Errors reach logs and findings, so they never echo the request.
func TestDecodeRequestErrorsDoNotEchoInput(t *testing.T) {
	for _, body := range []string{
		`{"csm_secret_key":"remove"}`,
		`{"operation":"csm_secret_op"}`,
		strings.Replace(validApply, `/run/rspamd/csm-normal.sock`, `/run/csm_secret_path.sock x`, 1),
		strings.TrimSuffix(validApply, "}") + `,"feeds":"csm_secret_feed"}`,
		strings.TrimSuffix(validApply, "}") + `,"skip_maps":"csm_secret_map"}`,
	} {
		if _, _, err := DecodeRequest([]byte(body)); err == nil || strings.Contains(err.Error(), "csm_secret") {
			t.Errorf("DecodeRequest(%s) = %v", body, err)
		}
	}
}

func TestParseResult(t *testing.T) {
	r, err := ParseResult([]byte(`{"operation":"apply","ok":false,"busy":true,"failed_step":"lock","rollback":"none","error":"held"}` + "\n"))
	if err != nil || !r.Busy || r.OK || r.FailedStep != "lock" || r.Rollback != RollbackNone {
		t.Fatalf("ParseResult = %+v, %v", r, err)
	}
	for _, out := range []string{``, `not json`, `{"ok":true,"extra":1}`, `{"ok":true}{"ok":true}`, `[]`} {
		if _, err := ParseResult([]byte(out)); err == nil {
			t.Errorf("ParseResult(%q) accepted", out)
		}
	}
}

func TestParseResultRoundTrip(t *testing.T) {
	for name, want := range map[string]Result{
		"apply":            {Operation: OpApply, OK: true, Generation: "g1"},
		"remove":           {Operation: OpRemove, OK: true},
		"unchanged":        {Operation: OpApply, OK: true, Rollback: RollbackNone, Generation: "g1"},
		"request error":    {FailedStep: "request", Rollback: RollbackNone, Error: "invalid request"},
		"lock error":       {Operation: OpRemove, FailedStep: "lock", Rollback: RollbackNone, Error: "cannot lock"},
		"busy":             {Operation: OpApply, Busy: true, FailedStep: "lock", Rollback: RollbackNone, Error: "held"},
		"precondition":     {Operation: OpApply, FailedStep: "preconditions", Rollback: RollbackNone},
		"rolled back":      {Operation: OpRemove, FailedStep: "reload", Rollback: RollbackVerified, Error: "reload failed"},
		"unverified":       {Operation: OpApply, FailedStep: "probe", Rollback: RollbackFailed, Error: "probe failed"},
		"Roundcube apply":  {Operation: OpApply, OK: true, Generation: "g1", Roundcube: RoundcubeUnavailable + "PHP failed"},
		"Roundcube remove": {Operation: OpRemove, OK: true, Roundcube: RoundcubeUnavailable + "another include sets the folder"},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseResult(append(data, '\n'))
			if err != nil || got != want {
				t.Fatalf("ParseResult = %+v, %v; want %+v", got, err, want)
			}
		})
	}
}

func TestParseResultRejectsMalformedReports(t *testing.T) {
	const success = `{"operation":"apply","ok":true,"generation":"g1"}`
	for name, out := range map[string]string{
		"null":                      `null`,
		"empty object":              `{}`,
		"missing ok":                `{"operation":"apply","generation":"g1"}`,
		"null ok":                   `{"operation":"apply","ok":null,"generation":"g1"}`,
		"duplicate ok":              `{"operation":"apply","ok":false,"ok":true,"generation":"g1"}`,
		"escaped duplicate ok":      `{"operation":"apply","ok":false,"\u006fk":true,"generation":"g1"}`,
		"case variant ok":           `{"operation":"apply","OK":true,"generation":"g1"}`,
		"case variant operation":    `{"Operation":"apply","ok":true,"generation":"g1"}`,
		"missing operation":         `{"ok":true,"generation":"g1"}`,
		"unknown operation":         `{"operation":"restart","ok":true}`,
		"missing generation":        `{"operation":"apply","ok":true}`,
		"remove generation":         `{"operation":"remove","ok":true,"generation":"g1"}`,
		"success with busy":         `{"operation":"apply","ok":true,"busy":true,"generation":"g1"}`,
		"success with failed step":  `{"operation":"apply","ok":true,"failed_step":"probe","generation":"g1"}`,
		"success with error":        `{"operation":"apply","ok":true,"error":"probe failed","generation":"g1"}`,
		"success rolled back":       `{"operation":"apply","ok":true,"rollback":"verified","generation":"g1"}`,
		"success rollback failed":   `{"operation":"apply","ok":true,"rollback":"failed","generation":"g1"}`,
		"unknown rollback":          `{"operation":"apply","ok":false,"failed_step":"probe","rollback":"maybe"}`,
		"failure without step":      `{"operation":"apply","ok":false,"rollback":"none"}`,
		"failure without rollback":  `{"operation":"apply","ok":false,"failed_step":"probe"}`,
		"failure without operation": `{"ok":false,"failed_step":"probe","rollback":"failed"}`,
		"failure with generation":   `{"operation":"apply","ok":false,"failed_step":"probe","rollback":"failed","generation":"g1"}`,
		"busy after changes":        `{"operation":"apply","ok":false,"busy":true,"failed_step":"lock","rollback":"failed"}`,
		"busy outside lock":         `{"operation":"apply","ok":false,"busy":true,"failed_step":"probe","rollback":"none"}`,
		"request changed state":     `{"ok":false,"failed_step":"request","rollback":"failed"}`,
		"lock changed state":        `{"operation":"remove","ok":false,"failed_step":"lock","rollback":"verified"}`,
		"Roundcube unknown":         `{"operation":"remove","ok":true,"roundcube":"installed"}`,
		"Roundcube failed":          `{"operation":"remove","ok":false,"failed_step":"probe","rollback":"failed","roundcube":"unavailable: PHP failed"}`,
		"trailing null":             success + `null`,
		"trailing junk":             success + `x`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseResult([]byte(out))
			if err == nil || got != (Result{}) {
				t.Fatalf("ParseResult = %+v, %v; want zero result and error", got, err)
			}
		})
	}
	for _, field := range []string{"operation", "ok", "busy", "failed_step", "rollback", "generation", "error", "roundcube"} {
		for name, value := range map[string]any{"null": nil, "wrong type": 123, "nested": map[string]any{"x": true}} {
			t.Run(name+" "+field, func(t *testing.T) {
				fields := map[string]any{"operation": "remove", "ok": false, "failed_step": "lock", "rollback": "none"}
				fields[field] = value
				out, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := ParseResult(out); err == nil || got != (Result{}) {
					t.Fatalf("ParseResult = %+v, %v; want zero result and error", got, err)
				}
			})
		}
	}
}

func TestParseResultErrorsDoNotEchoOutput(t *testing.T) {
	for _, out := range []string{
		`{"csm_private_field":"value","ok":true}`,
		`{"operation":"remove","ok":"csm_private_value"}`,
		`{"operation":"remove","ok":true,"error":123}`,
	} {
		if _, err := ParseResult([]byte(out)); err == nil || strings.Contains(err.Error(), "csm_private") {
			t.Fatalf("ParseResult = %v; want an error without worker output", err)
		}
	}
}

func TestApplyRequestCarriesFeedsButNeverTheKey(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL, FeedSpamhausDQS}
	s.SkipMaps = []string{RedirectWhitelist}
	s.DQSKeyFile = "/etc/csm/spamhaus-dqs.key"
	s.DQSKey = NewSecret("abcdefghijklmnopqrstu23456")
	data, err := json.Marshal(ApplyRequest(s))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abcdefghijklmnopqrstu23456") {
		t.Fatalf("request carries the key: %s", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Feeds, s.Feeds) || !slices.Equal(got.SkipMaps, s.SkipMaps) || got.DQSKeyFile != s.DQSKeyFile || got.DQSKey.Reveal() != "" {
		t.Fatalf("decoded %+v", got)
	}
}

func TestApplyRequestWithoutFeedsKeepsItsFormat(t *testing.T) {
	data, _ := json.Marshal(ApplyRequest(defaults(true)))
	want := `{"operation":"apply","enabled":true,"dry_run":true,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6}`
	if string(data) != want {
		t.Fatalf("got %s, want %s", data, want)
	}
}

func TestDecodeRequestRejectsBadFeedFields(t *testing.T) {
	base := `{"operation":"apply","enabled":true,"dry_run":true,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6`
	for _, extra := range []string{
		`,"feeds":"nope"}`,
		`,"feeds":"psbl,psbl"}`,
		`,"feeds":"psbl,"}`,
		`,"feeds":"spamhaus_dqs"}`,
		`,"skip_maps":"nope"}`,
		`,"feeds":["psbl"]}`,
		`,"feeds":null}`,
		`,"skip_maps":null}`,
		`,"dqs_key_file":null}`,
	} {
		if req, s, err := DecodeRequest([]byte(base + extra)); err == nil || !reflect.DeepEqual(req, Request{}) || !reflect.DeepEqual(s, Settings{}) {
			t.Errorf("expected rejection without a partial request for %s", extra)
		}
	}
	if _, _, err := DecodeRequest([]byte(`{"operation":"remove","feeds":"psbl"}`)); err == nil {
		t.Error("remove accepted feeds")
	}
}

func TestDecodeRequestEmptyFeedFields(t *testing.T) {
	body := strings.TrimSuffix(validApply, "}") + `,"feeds":"","skip_maps":"","dqs_key_file":""}`
	req, s, err := DecodeRequest([]byte(body))
	if err != nil || req.Operation != OpApply || !reflect.DeepEqual(s, defaults(false)) {
		t.Fatalf("expected default settings, got %+v, %v", s, err)
	}
}

func TestRequestRoundTripLearning(t *testing.T) {
	want := defaults(true)
	want.Learning, want.LearningDir, want.Roundcube = true, DefaultLearningDir, true
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxRequestBytes {
		t.Fatalf("request is %d bytes", len(data))
	}
	if !strings.Contains(string(data), `"learning":true,"learning_dir":"/var/lib/csm/antispam/learning","roundcube":true`) {
		t.Fatalf("wire form = %s", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeRequest = %+v, %v", got, err)
	}
	if _, _, err := DecodeRequest([]byte(strings.Replace(string(data), `"roundcube"`, `"Roundcube"`, 1))); err == nil {
		t.Fatal("case-folded key accepted")
	}
	for _, bad := range []string{`"learning":"true"`, `"learning":null`, `"learning_dir":7`, `"roundcube":1`, `"roundcube":null`, `"learning_keys":"x"`} {
		body := validApply[:len(validApply)-1] + `,` + bad + `}`
		if _, _, err := DecodeRequest([]byte(body)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	off, _ := json.Marshal(ApplyRequest(defaults(true)))
	if strings.Contains(string(off), "learning") || strings.Contains(string(off), "roundcube") {
		t.Fatalf("request without learning changed format: %s", off)
	}
}

func TestDecodeRequestInactiveLearningDir(t *testing.T) {
	for _, flags := range []string{"", `,"learning":false,"roundcube":false`} {
		t.Run(flags, func(t *testing.T) {
			body := strings.TrimSuffix(validApply, "}") + flags + `,"learning_dir":"/var/lib/csm/antispam/learning"}`
			_, got, err := DecodeRequest([]byte(body))
			if err != nil || !reflect.DeepEqual(got, defaults(false)) {
				t.Fatalf("inactive learning changed settings: %+v, %v", got, err)
			}
			encoded, err := json.Marshal(ApplyRequest(got))
			if err != nil || string(encoded) != validApply {
				t.Fatalf("inactive learning changed request: %s, %v", encoded, err)
			}
		})
	}
}

func TestSettingsValidateLearningDir(t *testing.T) {
	for _, dir := range []string{"", "relative/learning", "/var/lib/csm/../learning", "/var/lib/csm/learning/", "/var/lib/csm//learning", "/var/lib/csm/learn\ning"} {
		s := defaults(true)
		s.Learning, s.LearningDir = true, dir
		if err := s.Validate(); err == nil {
			t.Fatalf("LearningDir %q accepted", dir)
		}
	}
	s := defaults(true)
	s.Learning, s.LearningDir = true, DefaultLearningDir
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsValidateRoundcubeNeedsLearning(t *testing.T) {
	s := defaults(true)
	s.Roundcube = true
	if err := s.Validate(); err == nil {
		t.Fatal("Roundcube without Learning accepted")
	}
}

func TestRequestRoundTripHostScores(t *testing.T) {
	want := defaults(false)
	want.HostScores = []string{"HIDDEN_TEXT", "DMARC_POLICY_REJECT"}
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"host_scores":"HIDDEN_TEXT,DMARC_POLICY_REJECT"`) {
		t.Fatalf("request %s lacks host_scores", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	if data, err = json.Marshal(ApplyRequest(defaults(false))); err != nil || strings.Contains(string(data), "host_scores") {
		t.Fatalf("request without host weights %s, %v", data, err)
	}
	for _, bad := range [][]string{{"R_SPF_FAIL"}, {"HIDDEN_TEXT", "HIDDEN_TEXT"}, {""}} {
		s := defaults(false)
		s.HostScores = bad
		if err := s.Validate(); err == nil {
			t.Fatalf("host scores %q accepted", bad)
		}
	}
}

func TestDecodeRequestRejectsInvalidHostScores(t *testing.T) {
	for name, field := range map[string]string{
		"unknown":                 `"host_scores":"private_input"`,
		"duplicate unknown":       `"host_scores":"private_input,private_input"`,
		"duplicate symbol":        `"host_scores":"HIDDEN_TEXT,HIDDEN_TEXT"`,
		"empty name":              `"host_scores":"HIDDEN_TEXT,"`,
		"null":                    `"host_scores":null`,
		"boolean":                 `"host_scores":true`,
		"number":                  `"host_scores":1`,
		"array":                   `"host_scores":["HIDDEN_TEXT"]`,
		"object":                  `"host_scores":{}`,
		"duplicate field":         `"host_scores":"HIDDEN_TEXT","host_scores":"URL_VERY_LONG"`,
		"escaped duplicate field": `"host_scores":"HIDDEN_TEXT","host_\u0073cores":"URL_VERY_LONG"`,
		"case variant":            `"Host_Scores":"HIDDEN_TEXT"`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, skip := range []string{"", `,"skip_scores":true`} {
				body := strings.TrimSuffix(validApply, "}") + "," + field + skip + "}"
				r, s, err := DecodeRequest([]byte(body))
				if err == nil || strings.Contains(err.Error(), "private_input") || !reflect.DeepEqual(r, Request{}) || !reflect.DeepEqual(s, Settings{}) {
					t.Fatalf("invalid host_scores returned a request or unsafe error: %+v, %+v, %v", r, s, err)
				}
			}
		})
	}
}

func TestRequestRoundTripSkipScores(t *testing.T) {
	want := defaults(false)
	want.SkipScores = true
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"skip_scores":true`) {
		t.Fatalf("request %s lacks skip_scores", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	for _, extra := range []string{`,"skip_scores":"true"}`, `,"skip_scores":null}`, `,"skip_scores":1}`} {
		if _, _, err := DecodeRequest([]byte(strings.TrimSuffix(validApply, "}") + extra)); err == nil {
			t.Errorf("accepted %s", extra)
		}
	}
	if _, _, err := DecodeRequest([]byte(`{"operation":"remove","skip_scores":true}`)); err == nil {
		t.Error("remove accepted skip_scores")
	}
}

// postfixScoped is a Postfix request with exemptions and infra_ips networks,
// which only the scope Lua renders.
func postfixScoped() Settings {
	s := defaults(false)
	s.Stack = StackPostfix
	s.Exempt = []string{"abuse@example.com", "example.org"}
	s.ScopeNets = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("198.51.100.7/32")}
	return s
}

// The worker renders what the daemon rendered: a Postfix request carries
// the exemptions and networks, in order, so both compute one generation.
func TestApplyRequestCarriesPostfixScope(t *testing.T) {
	want := postfixScoped()
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), `,"exempt":"abuse@example.com,example.org","scope_nets":"203.0.113.0/24,2001:db8::/32,198.51.100.7/32"}`) {
		t.Fatalf("wire form = %s", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	// The worker reads the stack from its host, never from the request.
	got.Stack = StackPostfix
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
	daemon, err := ManagedContent(want)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ManagedContent(got)
	if err != nil {
		t.Fatal(err)
	}
	if Generation(worker) != Generation(daemon) {
		t.Fatal("the worker renders a different generation from the daemon")
	}
}

// Exim renders neither field, so its requests keep their form.
func TestApplyRequestEximOmitsPostfixScope(t *testing.T) {
	s := postfixScoped()
	s.Stack = StackExim
	data, err := json.Marshal(ApplyRequest(s))
	if err != nil || string(data) != validApply {
		t.Fatalf("wire form = %s, %v; want %s", data, err, validApply)
	}
	// A request from before the fields existed decodes as it did.
	_, got, err := DecodeRequest([]byte(validApply))
	if err != nil || got.Exempt != nil || got.ScopeNets != nil {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	// Decoded settings name no stack and re-encode to the same request.
	s.Stack = StackPostfix
	want, _ := json.Marshal(ApplyRequest(s))
	_, decoded, err := DecodeRequest(want)
	if again, _ := json.Marshal(ApplyRequest(decoded)); err != nil || string(again) != string(want) {
		t.Fatalf("re-encoded %s, %v; want %s", again, err, want)
	}
}

func TestDecodeRequestRejectsBadPostfixScope(t *testing.T) {
	for _, extra := range []string{
		`,"exempt":"Abuse@Example.com"}`,
		`,"exempt":"a b@example.com"}`,
		`,"exempt":"example.com,"}`,
		`,"exempt":"*"}`,
		`,"exempt":["example.com"]}`,
		`,"exempt":null}`,
		`,"scope_nets":"203.0.113.0/33"}`,
		`,"scope_nets":"203.0.113.0"}`,
		`,"scope_nets":"203.0.113.0/24,"}`,
		`,"scope_nets":"fe80::1%eth0/64"}`,
		`,"scope_nets":7}`,
		`,"scope_nets":null}`,
	} {
		req, s, err := DecodeRequest([]byte(strings.TrimSuffix(validApply, "}") + extra))
		if err == nil || !reflect.DeepEqual(req, Request{}) || !reflect.DeepEqual(s, Settings{}) {
			t.Errorf("expected rejection without a partial request for %s", extra)
		}
	}
	// Errors reach logs and findings, so they never echo the request.
	for _, extra := range []string{`,"exempt":"csm_secret@example.com,CSM_SECRET"}`, `,"scope_nets":"csm_secret/24"}`} {
		if _, _, err := DecodeRequest([]byte(strings.TrimSuffix(validApply, "}") + extra)); err == nil || strings.Contains(strings.ToLower(err.Error()), "csm_secret") {
			t.Errorf("DecodeRequest(%s) = %v", extra, err)
		}
	}
	for _, field := range []string{`"exempt":"example.com"`, `"scope_nets":"203.0.113.0/24"`} {
		if _, _, err := DecodeRequest([]byte(`{"operation":"remove",` + field + `}`)); err == nil {
			t.Errorf("remove accepted %s", field)
		}
	}
}

// Records written before the learning Redis socket existed decode to the
// settings they always did and serialize to the same bytes, so the worker's
// record comparison keeps matching them.
func TestRequestWithoutRedisSocketDecodesAsBefore(t *testing.T) {
	learning := defaults(true)
	learning.Feeds, learning.SkipMaps = []string{FeedPSBL, FeedSpamhausDQS}, []string{RedirectWhitelist}
	learning.SkipScores, learning.DQSKeyFile = true, "/etc/csm/spamhaus-dqs.key"
	learning.Learning, learning.LearningDir, learning.Roundcube = true, DefaultLearningDir, true
	postfix := defaults(false)
	postfix.Learning, postfix.LearningDir = true, DefaultLearningDir
	postfix.Exempt = []string{"abuse@example.com", "example.org"}
	postfix.ScopeNets = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	for _, tc := range []struct {
		name, record string
		stack        MailStack
		want         Settings
	}{
		{"exim", validApply, StackExim, defaults(false)},
		{"exim learning",
			`{"operation":"apply","enabled":true,"dry_run":true,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6,"feeds":"psbl,spamhaus_dqs","skip_maps":"whitelist","skip_scores":true,"dqs_key_file":"/etc/csm/spamhaus-dqs.key","learning":true,"learning_dir":"/var/lib/csm/antispam/learning","roundcube":true}`,
			StackExim, learning},
		{"postfix learning",
			`{"operation":"apply","enabled":true,"dry_run":false,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6,"learning":true,"learning_dir":"/var/lib/csm/antispam/learning","exempt":"abuse@example.com,example.org","scope_nets":"203.0.113.0/24,2001:db8::/32"}`,
			StackPostfix, postfix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, got, err := DecodeRequest([]byte(tc.record))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DecodeRequest = %+v, %v; want %+v", got, err, tc.want)
			}
			if data, err := json.Marshal(req); err != nil || string(data) != tc.record {
				t.Fatalf("decoded request serializes to %s, %v; want %s", data, err, tc.record)
			}
			got.Stack = tc.stack
			if data, err := json.Marshal(ApplyRequest(got)); err != nil || string(data) != tc.record {
				t.Fatalf("ApplyRequest serializes to %s, %v; want %s", data, err, tc.record)
			}
		})
	}
}

// The learning Redis socket travels with learning, so the worker renders
// the same fuzzy worker the daemon did.
func TestRequestRoundTripLearningRedisSocket(t *testing.T) {
	want := defaults(false)
	want.Learning, want.LearningDir, want.LearningRedisSocket = true, DefaultLearningDir, "/run/redis-csm/redis.sock"
	data, err := json.Marshal(ApplyRequest(want))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), `,"learning":true,"learning_dir":"/var/lib/csm/antispam/learning","learning_redis_socket":"/run/redis-csm/redis.sock"}`) {
		t.Fatalf("wire form = %s", data)
	}
	_, got, err := DecodeRequest(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeRequest = %+v, %v; want %+v", got, err, want)
	}
	learning := strings.TrimSuffix(validApply, "}") + `,"learning":true,"learning_dir":"/var/lib/csm/antispam/learning"`
	for _, bad := range []string{
		`"learning_redis_socket":"run/redis.sock"`,
		`"learning_redis_socket":"/run/redis csm.sock"`,
		`"learning_redis_socket":"/run/redis\"csm.sock"`,
		`"learning_redis_socket":"/run/redis/../csm.sock"`,
		`"learning_redis_socket":7`,
		`"learning_redis_socket":null`,
		`"Learning_Redis_Socket":"/run/redis-csm/redis.sock"`,
	} {
		req, s, decodeErr := DecodeRequest([]byte(learning + `,` + bad + `}`))
		if decodeErr == nil || !reflect.DeepEqual(req, Request{}) || !reflect.DeepEqual(s, Settings{}) {
			t.Errorf("expected rejection without a partial request for %s", bad)
		}
	}
	// Without learning the socket is inactive, like the learning directory.
	_, got, err = DecodeRequest([]byte(strings.TrimSuffix(validApply, "}") + `,"learning_redis_socket":"/run/redis-csm/redis.sock"}`))
	if err != nil || !reflect.DeepEqual(got, defaults(false)) {
		t.Fatalf("inactive socket changed settings: %+v, %v", got, err)
	}
	off := want
	off.Learning = false
	if data, err := json.Marshal(ApplyRequest(off)); err != nil || string(data) != validApply {
		t.Fatalf("request without learning = %s, %v; want %s", data, err, validApply)
	}
	if _, _, err := DecodeRequest([]byte(`{"operation":"remove","learning_redis_socket":"/run/redis-csm/redis.sock"}`)); err == nil {
		t.Error("remove accepted learning_redis_socket")
	}
}

func TestSettingsValidateLearningRedisSocket(t *testing.T) {
	s := defaults(true)
	s.Learning, s.LearningDir = true, DefaultLearningDir
	for _, p := range []string{"run/redis.sock", "/run/redis csm.sock", `/run/redis"csm.sock`, "/run/redis/", "/run/redis.sock\n"} {
		s.LearningRedisSocket = p
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "redis_socket") || strings.Contains(err.Error(), "rspamd_socket") {
			t.Errorf("LearningRedisSocket %q: err = %v, want an error naming redis_socket", p, err)
		}
	}
	for _, p := range []string{"", "/run/redis-csm/redis.sock"} {
		s.LearningRedisSocket = p
		if err := s.Validate(); err != nil {
			t.Errorf("LearningRedisSocket %q: %v", p, err)
		}
	}
}

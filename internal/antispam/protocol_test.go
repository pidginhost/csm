package antispam

import (
	"encoding/json"
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
		"apply":         {Operation: OpApply, OK: true, Generation: "g1"},
		"remove":        {Operation: OpRemove, OK: true},
		"unchanged":     {Operation: OpApply, OK: true, Rollback: RollbackNone, Generation: "g1"},
		"request error": {FailedStep: "request", Rollback: RollbackNone, Error: "invalid request"},
		"lock error":    {Operation: OpRemove, FailedStep: "lock", Rollback: RollbackNone, Error: "cannot lock"},
		"busy":          {Operation: OpApply, Busy: true, FailedStep: "lock", Rollback: RollbackNone, Error: "held"},
		"precondition":  {Operation: OpApply, FailedStep: "preconditions", Rollback: RollbackNone},
		"rolled back":   {Operation: OpRemove, FailedStep: "reload", Rollback: RollbackVerified, Error: "reload failed"},
		"unverified":    {Operation: OpApply, FailedStep: "probe", Rollback: RollbackFailed, Error: "probe failed"},
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
	for _, field := range []string{"operation", "ok", "busy", "failed_step", "rollback", "generation", "error"} {
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

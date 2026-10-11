package antispam

import (
	"encoding/json"
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
	if err != nil || req.Operation != OpApply || got != want {
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
	if err != nil || req.Operation != OpRemove || s != (Settings{}) {
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

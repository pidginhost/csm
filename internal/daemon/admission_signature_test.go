package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/verdict"
)

// Admission accepts only signed, request-bound allows, even if the legacy
// callback has explicitly opted out of signing.
func TestExecutionPolicyRequiresSignedAllows(t *testing.T) {
	previous := config.Active()
	t.Cleanup(func() { config.SetActive(previous) })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(key)
	t.Setenv("CSM_ADMISSION_TEST_HMAC", secret)
	for _, tc := range []struct {
		name, answer          string
		secret, signed, bound bool
		want                  verdict.ErrorClass
	}{
		{name: "unsigned rollout", answer: "allow", want: verdict.ClassSignature},
		{name: "signature opt-out", answer: "allow", secret: true, bound: true, want: verdict.ClassSignature},
		{name: "unbound signed allow", answer: "allow", secret: true, signed: true, want: verdict.ClassReplay},
		{name: "signed allow", answer: "allow", secret: true, signed: true, bound: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req verdict.Request
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				resp := verdict.Response{Verdict: tc.answer}
				if tc.bound {
					resp.Nonce, resp.Timestamp = req.Nonce, time.Now().Unix()
				}
				body, err := json.Marshal(resp)
				if err != nil {
					t.Error(err)
					return
				}
				if tc.signed {
					mac := hmac.New(sha256.New, []byte(secret))
					_, _ = mac.Write(body)
					w.Header().Set("X-CSM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			body := "auto_response:\n  verdict_callback:\n    enabled: true\n    url: " + srv.URL + "\n    allow_unsigned: true\n    require_response_signature: false\n"
			if tc.secret {
				body += "    hmac_secret_env: CSM_ADMISSION_TEST_HMAC\n"
			}
			publishTestConfig(t, body)
			policy := (&Daemon{}).executionPolicy()
			resp, err := policy.AskVerdict(context.Background(), "192.0.2.10", "CSM auto-block: ssh_brute")
			if verdict.ClassOf(err) != tc.want || (err == nil) != (tc.want == "") {
				t.Fatalf("error class = %q, want %q", verdict.ClassOf(err), tc.want)
			}
			if tc.want == "" && resp.Verdict != "allow" {
				t.Fatal("signed allow was not accepted")
			}
		})
	}
}

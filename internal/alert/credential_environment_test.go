//go:build !windows

package alert_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/threatintel"
	"github.com/pidginhost/csm/internal/verdict"
)

const credentialTestEnv = "CSM_TEST_ENV_CREDENTIAL"
const credentialTestURL = "CSM_TEST_ENV_CREDENTIAL_URL"

// Editing a launch environment file leaves every client's credentials unchanged
// until the process restarts and inherits the replacement environment.
func TestEnvironmentCredentialRotation(t *testing.T) {
	if endpoint := os.Getenv(credentialTestURL); endpoint != "" {
		runCredentialRequests(t, endpoint)
		return
	}
	const oldSecret, newSecret = "test-before-restart", "test-after-restart"
	type request struct {
		path, token, signature string
		body                   []byte
	}
	requests := make(chan request, 12)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := r.Header.Get("Authorization")
		if r.URL.Path == "/rspamd/history" {
			token = r.Header.Get("Password")
		}
		signature := r.Header.Get("X-CSM-Signature")
		requests <- request{r.URL.Path, token, signature, body}
		var response []byte
		switch r.URL.Path {
		case "/upstream/lookup":
			response, err = json.Marshal(map[string]any{"ip": r.URL.Query().Get("ip"), "score": 75})
		case "/rspamd/history":
			response = []byte(`{"rows":[]}`)
		case "/verdict":
			var req verdict.Request
			if err = json.Unmarshal(body, &req); err == nil {
				response, err = json.Marshal(verdict.Response{Verdict: "block", Nonce: req.Nonce, Timestamp: time.Now().Unix()})
			}
			secret := oldSecret
			if signature == credentialSignature(newSecret, body) {
				secret = newSecret
			}
			w.Header().Set("X-CSM-Signature", credentialSignature(secret, response))
		case "/webhook":
			response = []byte(`{}`)
		default:
			t.Errorf("unexpected endpoint %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			t.Errorf("response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(response); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	checkRequests := func(secret string) {
		t.Helper()
		for _, path := range []string{"/upstream/lookup", "/rspamd/history", "/verdict", "/webhook"} {
			select {
			case got := <-requests:
				if got.path != path {
					t.Fatalf("request path = %q, want %q", got.path, path)
				}
				switch path {
				case "/upstream/lookup":
					if got.token != "Bearer "+secret {
						t.Errorf("upstream used unexpected credential")
					}
				case "/rspamd/history":
					if got.token != secret {
						t.Errorf("rspamd used unexpected credential")
					}
				default:
					if got.signature != credentialSignature(secret, got.body) {
						t.Errorf("%s used unexpected signing credential", path)
					}
				}
			case <-ctx.Done():
				t.Fatalf("missing %s request: %v", path, ctx.Err())
			}
		}
	}
	envFile := filepath.Join(t.TempDir(), "credentials.env")
	writeSecret := func(secret string) {
		t.Helper()
		if err := os.WriteFile(envFile, []byte(credentialTestEnv+"="+secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSecret(oldSecret)
	probe, stop := startCredentialProcess(t, ctx, srv.URL, envFile)
	probe("192.0.2.1")
	checkRequests(oldSecret)
	writeSecret(newSecret)
	probe("192.0.2.2")
	checkRequests(oldSecret)
	stop()
	probe, stop = startCredentialProcess(t, ctx, srv.URL, envFile)
	probe("192.0.2.3")
	checkRequests(newSecret)
	stop()
	if len(requests) != 0 {
		t.Fatalf("unexpected extra requests: %d", len(requests))
	}
}

func credentialSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func startCredentialProcess(t *testing.T, ctx context.Context, endpoint, envFile string) (probe func(string), stop func()) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The launcher reads the file only at process creation, as EnvironmentFile
	// does for a service. No test mutates the running child's environment.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `set -a; . "$1"; exec "$2" -test.run=^TestEnvironmentCredentialRotation$`, "--", envFile, executable)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, credentialTestEnv+"=") && !strings.HasPrefix(entry, credentialTestURL+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, credentialTestURL+"="+endpoint)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	stop = func() {
		t.Helper()
		if err := stdin.Close(); err != nil {
			t.Error(err)
		}
		err := cmd.Wait()
		waited = true
		if err != nil {
			t.Fatalf("credential process: %v\n%s", err, stderr.String())
		}
	}
	scanner := bufio.NewScanner(stdout)
	probe = func(ip string) {
		t.Helper()
		if _, err := fmt.Fprintln(stdin, ip); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() || scanner.Text() != "sent" {
			t.Fatalf("credential process did not finish requests: %q (%v)", scanner.Text(), scanner.Err())
		}
	}
	return probe, stop
}

func runCredentialRequests(t *testing.T, endpoint string) {
	t.Helper()
	upstream := threatintel.NewUpstreamSource(threatintel.UpstreamConfig{URL: endpoint + "/upstream", TokenEnv: credentialTestEnv})
	rspamd := threatintel.NewRspamdSource(endpoint+"/rspamd", "", credentialTestEnv)
	callback := verdict.New(verdict.Config{URL: endpoint + "/verdict", HMACSecretEnv: credentialTestEnv})
	cfg := &config.Config{Hostname: "credential-test"}
	cfg.Alerts.Webhook.URL = endpoint + "/webhook"
	cfg.Alerts.Webhook.HMACSecretEnv = credentialTestEnv
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ip := scanner.Text()
		ctx := context.Background()
		if score, err := upstream.Score(ctx, ip); err != nil || score != 75 {
			t.Fatalf("upstream: score %d, error %v", score, err)
		}
		if score, err := rspamd.Score(ctx, ip); err != nil || score != 0 {
			t.Fatalf("rspamd: score %d, error %v", score, err)
		}
		if response, err := callback.Ask(ctx, verdict.Request{IP: ip, Reason: "credential-test"}); err != nil || response.Verdict != "block" {
			t.Fatalf("verdict: response %+v, error %v", response, err)
		}
		if err := alert.SendPhpanelWebhookFinding(cfg, alert.Finding{Check: "credential-test"}); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Println("sent"); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

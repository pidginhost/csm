package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// mockShadowLogs wires osFS so tailFile can read fixed contents for the
// cPanel session_log and api_tokens_log paths. Any other Open call returns
// ErrNotExist.
func mockShadowLogs(t *testing.T, sessionLog, apiTokensLog string) {
	t.Helper()
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "session_log")
	tokensPath := filepath.Join(dir, "api_tokens_log")
	if err := os.WriteFile(sessionPath, []byte(sessionLog), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokensPath, []byte(apiTokensLog), 0o644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			switch {
			case strings.Contains(name, "session_log"):
				return os.Open(sessionPath)
			case strings.Contains(name, "api_tokens_log"):
				return os.Open(tokensPath)
			}
			return nil, os.ErrNotExist
		},
	})
}

func TestIsInfraShadowChange_SuspendAcctFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=avocatbeleutaro&reason=Suspend&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: suspendacct from infra IP must suppress shadow_change alert")
	}
}

func TestIsInfraShadowChange_SuspendAcctFromExternalIP(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['203.0.113.5'] HTTP Status: ['200'], User: ['attacker'], Token Name: ['stolen'], Request: ['GET /json-api/suspendacct?user=victim&reason=evil&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: suspendacct from external IP must NOT suppress (possible attack)")
	}
}

func TestIsInfraShadowChange_UnsuspendAcctFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 11:02:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/unsuspendacct?user=avocatbeleutaro&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: unsuspendacct from infra IP must suppress")
	}
}

func TestIsInfraShadowChange_PasswdEndpointFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 11:30:00 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['POST /json-api/passwd?user=foo&password=secret&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: WHM passwd endpoint from infra IP must suppress")
	}
}

func TestIsInfraShadowChange_CreateAcctFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 09:00:00 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['POST /json-api/createacct?username=newuser&password=secret&domain=example.com&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: createacct from infra IP must suppress (adds shadow entry)")
	}
}

func TestIsInfraShadowChange_RemoveAcctFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 09:30:00 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/removeacct?user=olduser&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: removeacct from infra IP must suppress (removes shadow entry)")
	}
}

func TestIsInfraShadowChange_KillAcctFromInfraIP(t *testing.T) {
	apiTokens := `[2026-05-19 09:30:00 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/killacct?user=olduser&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: killacct from infra IP must suppress (removes shadow entry)")
	}
}

func TestIsInfraShadowChange_MixedInfraSessionExternalToken(t *testing.T) {
	sessionLog := `[2026-05-19 10:00:00 +0300] info [whostmgr] 10.0.0.1 PURGE admin:abcdefghijklmnop password_change` + "\n"
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['203.0.113.5'] HTTP Status: ['200'], User: ['attacker'], Token Name: ['stolen'], Request: ['GET /json-api/suspendacct?user=victim&reason=evil&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, sessionLog, apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: external suspendacct present alongside infra password_change must NOT suppress")
	}
}

func TestIsInfraShadowChange_MalformedSessionSourceDoesNotSuppress(t *testing.T) {
	sessionLog := `[2026-05-19 10:00:00 +0300] info [whostmgr] PURGE admin:abcdefghijklmnop password_change` + "\n"
	mockShadowLogs(t, sessionLog, "")

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: session password_change without a source IP must not suppress")
	}
}

func TestIsInfraShadowChange_NonShadowEndpointIgnored(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['203.0.113.5'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/listaccts?api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	// listaccts does not touch /etc/shadow, so api_tokens_log contributes
	// neither foundAny nor allInfra=false. With no session_log events either,
	// foundAny stays false -> return false (no suppression signal).
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: non-shadow endpoints must not produce suppression signal")
	}
}

func TestIsInfraShadowChange_SuspendAcctLoopback(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['127.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['localcron'], Request: ['GET /json-api/suspendacct?user=foo&reason=Suspend&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: suspendacct over loopback must suppress")
	}
}

func TestIsInfraShadowChange_SuspendAcctIPv6Loopback(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['::1'] HTTP Status: ['200'], User: ['root'], Token Name: ['localcron'], Request: ['GET /json-api/suspendacct?user=foo&reason=Suspend&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: suspendacct over IPv6 loopback must suppress")
	}
}

func TestIsInfraShadowChange_FailedSuspendAcctDoesNotSuppress(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['403'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=foo&reason=Suspend&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: failed suspendacct must not suppress an unrelated shadow_change")
	}
}

func TestIsInfraShadowChange_MissingAPITokenHostDoesNotSuppress(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=foo&reason=Suspend&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: successful API token line without host must not suppress")
	}
}

func TestIsInfraShadowChange_EndpointMustMatchRequestPath(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/passwdless?user=foo&api.version=1 HTTP/1.1']` + "\n"
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: endpoint substring matches must not suppress")
	}
}

func TestIsInfraShadowChange_MultipleSuspendsAllInfra(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=a&reason=Suspend&api.version=1 HTTP/1.1']
[2026-05-19 10:02:10 +0300] info [whostmgrd] Host: ['10.0.0.2'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=b&reason=Suspend&api.version=1 HTTP/1.1']
`
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if !isInfraShadowChange(cfg) {
		t.Fatal("expected true: multiple suspends all from infra must suppress")
	}
}

func TestIsInfraShadowChange_OneInfraOneExternalSuspend(t *testing.T) {
	apiTokens := `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['GET /json-api/suspendacct?user=a&reason=Suspend&api.version=1 HTTP/1.1']
[2026-05-19 10:02:10 +0300] info [whostmgrd] Host: ['203.0.113.5'] HTTP Status: ['200'], User: ['attacker'], Token Name: ['stolen'], Request: ['GET /json-api/suspendacct?user=victim&reason=evil&api.version=1 HTTP/1.1']
`
	mockShadowLogs(t, "", apiTokens)

	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	if isInfraShadowChange(cfg) {
		t.Fatal("expected false: any external suspendacct must defeat suppression")
	}
}

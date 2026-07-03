package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// The api_tokens_log / session_log events below are logged at
// 2026-05-19 10:01:10 +0300 == 2026-05-19 07:01:10 UTC.
const shadowEventPasswd = `[2026-05-19 10:01:10 +0300] info [whostmgrd] Host: ['10.0.0.1'] HTTP Status: ['200'], User: ['root'], Token Name: ['phclient'], Request: ['POST /json-api/passwd?user=foo&password=secret&api.version=1 HTTP/1.1']` + "\n"

const shadowEventSession = `[2026-05-19 10:00:00 +0300] info [whostmgr] 10.0.0.1 PURGE admin:abcdefghijklmnop password_change` + "\n"

const untimedExternalShadowTokenEvent = `info [whostmgrd] Host: ['203.0.113.5'] HTTP Status: ['200'], User: ['root'], Token Name: ['stolen'], Request: ['POST /json-api/passwd?user=foo&password=secret&api.version=1 HTTP/1.1']` + "\n"

const untimedExternalShadowSessionEvent = `info [xml-api] 203.0.113.5 PURGE admin:abcdefghijklmnop password_change` + "\n"

// TestIsInfraShadowChange_StaleTokenEventDoesNotSuppress reproduces CHK-10: a
// legitimate infra password change logged BEFORE the shadow file's recorded
// mtime must not suppress a newer, unexplained /etc/shadow modification (an
// attacker's direct edit leaves no fresh log event of its own).
func TestIsInfraShadowChange_StaleTokenEventDoesNotSuppress(t *testing.T) {
	mockShadowLogs(t, "", shadowEventPasswd)
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	// Shadow last recorded a full day after the infra event -> the event is
	// stale relative to the change under investigation.
	since := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	if isInfraShadowChange(cfg, since) {
		t.Fatal("stale infra token event older than shadow mtime must not suppress")
	}
}

func TestIsInfraShadowChange_StaleSessionEventDoesNotSuppress(t *testing.T) {
	mockShadowLogs(t, shadowEventSession, "")
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	since := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	if isInfraShadowChange(cfg, since) {
		t.Fatal("stale infra session event older than shadow mtime must not suppress")
	}
}

// TestIsInfraShadowChange_FreshTokenEventSuppresses is the companion: an infra
// event newer than the shadow mtime explains the change and must suppress.
func TestIsInfraShadowChange_FreshTokenEventSuppresses(t *testing.T) {
	mockShadowLogs(t, "", shadowEventPasswd)
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	// Shadow previously recorded before the infra event fired.
	since := time.Date(2026, 5, 19, 6, 0, 0, 0, time.UTC)
	if !isInfraShadowChange(cfg, since) {
		t.Fatal("fresh infra token event newer than shadow mtime must suppress")
	}
}

func TestIsInfraShadowChange_FreshSessionEventSuppresses(t *testing.T) {
	mockShadowLogs(t, shadowEventSession, "")
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	since := time.Date(2026, 5, 19, 6, 0, 0, 0, time.UTC)
	if !isInfraShadowChange(cfg, since) {
		t.Fatal("fresh infra session event newer than shadow mtime must suppress")
	}
}

func TestIsInfraShadowChange_LogSecondEqualStoredMtimeSuppresses(t *testing.T) {
	mockShadowLogs(t, "", shadowEventPasswd)
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	// cPanel logs only whole seconds. An event that really happened after this
	// stored mtime within the same second is logged as equal to that second, so
	// second-granularity equality must remain inside the suppression window.
	since := time.Date(2026, 5, 19, 7, 1, 10, int(500*time.Millisecond), time.UTC)
	if !isInfraShadowChange(cfg, since) {
		t.Fatal("infra event in the same logged second as shadow mtime must suppress")
	}
}

func TestIsInfraShadowChange_UntimedTokenEventDefeatsSuppression(t *testing.T) {
	mockShadowLogs(t, "", shadowEventPasswd+untimedExternalShadowTokenEvent)
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	since := time.Date(2026, 5, 19, 6, 0, 0, 0, time.UTC)
	if isInfraShadowChange(cfg, since) {
		t.Fatal("untimed shadow-mutating token line must fail toward alerting")
	}
}

func TestIsInfraShadowChange_UntimedSessionEventDefeatsSuppression(t *testing.T) {
	mockShadowLogs(t, shadowEventSession+untimedExternalShadowSessionEvent, "")
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}

	since := time.Date(2026, 5, 19, 6, 0, 0, 0, time.UTC)
	if isInfraShadowChange(cfg, since) {
		t.Fatal("untimed shadow-mutating session line must fail toward alerting")
	}
}

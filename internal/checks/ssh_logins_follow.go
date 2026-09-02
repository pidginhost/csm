package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const sshLoginFollowKey = "_ssh_login_follow"

// sshLoginLookback bounds how far back a first run or a large read gap
// reports accepted logins. Anything older is history, not a new login, and
// ssh_login_unknown_ip is a critical, always-block finding.
const sshLoginLookback = time.Hour

var sshLoginMu sync.Mutex

type sshLoginFollow struct {
	Follow followState `json:"follow"`
}

func loadSSHLoginFollow(store *state.Store) followState {
	raw, ok := store.GetRaw(sshLoginFollowKey)
	if !ok || raw == "" {
		return followState{}
	}
	var decoded sshLoginFollow
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil || invalidFollowState(decoded.Follow) {
		return followState{}
	}
	return decoded.Follow
}

func saveSSHLoginFollow(store *state.Store, st followState) {
	b, err := json.Marshal(sshLoginFollow{Follow: st})
	if err != nil {
		return
	}
	if err := store.SetRawAndSave(sshLoginFollowKey, string(b)); err != nil {
		fmt.Fprintf(os.Stderr, "state: error saving SSH login follow state: %v\n", err)
	}
}

// checkSSHLoginsFollow reads the auth log forward from the stored offset, so
// a login is seen however much brute-force noise follows it before the next
// cycle, and skips logins older than sshLoginLookback (first-run catch-up).
func checkSSHLoginsFollow(cfg *config.Config, store *state.Store) []alert.Finding {
	sshLoginMu.Lock()
	defer sshLoginMu.Unlock()

	st := loadSSHLoginFollow(store)
	lines, next, _, err := readNewSyslogLines(authLogPath(), st)
	if err != nil {
		return nil // leave stored state untouched
	}
	now := time.Now()
	cutoff := now.Add(-sshLoginLookback)

	var findings []alert.Finding
	for _, line := range lines {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		if at, ok := syslogLineTime(line, now); ok && at.Before(cutoff) {
			continue
		}
		if f, ok := sshAcceptedLoginFinding(line, cfg); ok {
			findings = append(findings, f)
		}
	}
	saveSSHLoginFollow(store, next)
	return findings
}

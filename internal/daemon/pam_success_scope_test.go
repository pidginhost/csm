package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// One successful PAM login used to erase the source's whole failure record
// and its credential-stuffing breadth, whichever account succeeded. An
// attacker walking many accounts from one IP who finally lands one (or who
// holds one valid account of their own) reset the count against every other
// account. A success clears only the failures attributed to that user.
func TestPAMSuccessClearsOnlyThatUsersFailures(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.PAMBruteforceThreshold = 100
	cfg.Thresholds.PAMBruteforceWindowMin = 60
	cfg.Thresholds.CredStuffingDistinctAccounts = 3
	p := &PAMListener{cfg: cfg, failures: map[string]*pamFailureTracker{}}
	const ip = "198.51.100.40"
	for _, user := range []string{"alice", "bob", "carol", "carol", "carol"} {
		p.recordFailure(ip, user, "sshd")
	}

	p.clearFailuresForUser(ip, "carol")

	tracker, ok := p.failures[ip]
	if !ok {
		t.Fatal("one user's success erased the failures recorded against the other users")
	}
	if tracker.users["carol"] || !tracker.users["alice"] || !tracker.users["bob"] {
		t.Fatalf("users after carol's success = %v, want alice and bob only", tracker.users)
	}
	if tracker.count != 2 {
		t.Fatalf("failure count after clearing carol = %d, want the two failures against alice and bob", tracker.count)
	}
	accounts, _ := p.stuffing.Record(ip, "dave")
	if len(accounts) < 3 {
		t.Fatalf("credential-stuffing breadth after one success = %v, want alice, bob and dave still counted", accounts)
	}

	p.clearFailuresForUser(ip, "alice")
	p.clearFailuresForUser(ip, "bob")
	if _, ok := p.failures[ip]; ok {
		t.Fatal("tracker survived after every failed user succeeded")
	}
}

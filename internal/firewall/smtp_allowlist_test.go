package firewall

import (
	"fmt"
	"os/user"
	"reflect"
	"testing"
)

// fixtureLookupUser builds a Lookup-shaped stub for resolveSMTPAllowedUIDs
// tests so they do not depend on /etc/passwd entries that may not exist on
// every test host.
func fixtureLookupUser(t *testing.T, table map[string]string) func(string) (*user.User, error) {
	t.Helper()
	return func(name string) (*user.User, error) {
		uid, ok := table[name]
		if !ok {
			return nil, fmt.Errorf("user: unknown user %q", name)
		}
		return &user.User{Uid: uid, Username: name}, nil
	}
}

func TestResolveSMTPAllowedUIDsAlwaysIncludesRoot(t *testing.T) {
	prev := smtpAllowlistLookupUser
	smtpAllowlistLookupUser = fixtureLookupUser(t, map[string]string{})
	t.Cleanup(func() { smtpAllowlistLookupUser = prev })

	got := resolveSMTPAllowedUIDs(nil)
	if len(got) == 0 || got[0] != 0 {
		t.Fatalf("resolveSMTPAllowedUIDs([]) = %v, want first entry 0 (root)", got)
	}
}

// TestResolveSMTPAllowedUIDsAlwaysIncludesMailnull is the regression guard
// for the scenario where smtp_allow_users lists cpanel + a handful of
// cpanel accounts + root but NOT mailnull. Exim's queue runner switches to
// mailnull for delivery, so its SYN packets to port 25 are dropped by the
// engine's allow-list. The queue grinds to a halt while CSM keeps
// reporting healthy.
func TestResolveSMTPAllowedUIDsAlwaysIncludesMailnull(t *testing.T) {
	prev := smtpAllowlistLookupUser
	smtpAllowlistLookupUser = fixtureLookupUser(t, map[string]string{
		"mailnull": "47",
		"cpanel":   "201",
	})
	t.Cleanup(func() { smtpAllowlistLookupUser = prev })

	got := resolveSMTPAllowedUIDs([]string{"cpanel"})
	has := func(uid uint32) bool {
		for _, x := range got {
			if x == uid {
				return true
			}
		}
		return false
	}
	if !has(47) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, missing mailnull (UID 47) -- queued mail will be silently dropped by the OUTPUT chain", got)
	}
	if !has(0) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, missing root (UID 0)", got)
	}
	if !has(201) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, missing operator-supplied cpanel (UID 201)", got)
	}
}

func TestResolveSMTPAllowedUIDsDedupsRootMailnullAndConfig(t *testing.T) {
	prev := smtpAllowlistLookupUser
	smtpAllowlistLookupUser = fixtureLookupUser(t, map[string]string{
		"mailnull": "47",
		"root":     "0",
		"alice":    "1001",
	})
	t.Cleanup(func() { smtpAllowlistLookupUser = prev })

	got := resolveSMTPAllowedUIDs([]string{"root", "mailnull", "alice", "alice"})
	want := []uint32{0, 47, 1001}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, want %v (root + mailnull + alice, no duplicates)", got, want)
	}
}

func TestResolveSMTPAllowedUIDsSkipsUnknownUsers(t *testing.T) {
	prev := smtpAllowlistLookupUser
	smtpAllowlistLookupUser = fixtureLookupUser(t, map[string]string{
		"mailnull": "47",
		"valid":    "1001",
	})
	t.Cleanup(func() { smtpAllowlistLookupUser = prev })

	got := resolveSMTPAllowedUIDs([]string{"valid", "ghost", "alsoghost"})
	want := []uint32{0, 47, 1001}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, want %v (unknown users skipped, not fatal)", got, want)
	}
}

func TestResolveSMTPAllowedUIDsMailnullAbsentDoesNotCrash(t *testing.T) {
	prev := smtpAllowlistLookupUser
	smtpAllowlistLookupUser = fixtureLookupUser(t, map[string]string{
		"cpanel": "201",
	})
	t.Cleanup(func() { smtpAllowlistLookupUser = prev })

	got := resolveSMTPAllowedUIDs([]string{"cpanel"})
	want := []uint32{0, 201}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolveSMTPAllowedUIDs = %v, want %v (mailnull absent on host -> only root + cpanel)", got, want)
	}
}

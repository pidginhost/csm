package checks

import "testing"

// A customer uploaded a file in cPanel File Manager and was firewall-blocked
// one second later:
//
//	16:21:33  cpanel_file_upload_realtime  POST /execute/Fileman/upload_files
//	16:21:34  auto_block                   AUTO-BLOCK: <ip> blocked (expires in 24h0m0s)
//
// Five more addresses were blocked for logging in to FTP successfully --
// pure-ftpd had already written "is now logged in" for each.
//
// These checks fire on operations that SUCCEEDED, after authentication. The
// producing handler even skips 401 and 403 so it only reports authenticated
// writes. On shared hosting every customer is a "non-infra IP", so the signal
// fires on ordinary use of core cPanel features -- uploading, saving,
// renaming, deleting, or simply logging in.
//
// The reasoning is already recorded in this file for cpanel_login:
// "a single event is not brute-force evidence. Blocking on one Warning turns
// a legitimate customer logging in from a new country into a 24h lockout."
// The same is true here; these three were missed.
//
// They stay as findings. During a live compromise "File Manager write from an
// address never seen before, on an account whose password just changed" is
// worth correlating. It is not a verdict on its own.
func TestSuccessfulAuthOperationsAreNeverBlockable(t *testing.T) {
	successAfterAuth := []string{
		"cpanel_file_upload_realtime",
		"ftp_login_realtime",
		"webmail_login_realtime",
	}
	for _, check := range successAfterAuth {
		for _, blockCpanelLogins := range []bool{false, true} {
			if blockableCheck(check, blockCpanelLogins) {
				t.Errorf("%s is block-eligible with block_cpanel_logins=%v; a successful authenticated operation must not trigger a firewall block",
					check, blockCpanelLogins)
			}
		}
	}
}

// The switch still has to do its job: failure and threshold checks are real
// evidence and must keep blocking when the operator turns it on. Removing
// those would trade one outage for another.
func TestFailureChecksStayBlockableWhenEnabled(t *testing.T) {
	failureEvidence := []string{
		"cpanel_multi_ip_login",
		"api_auth_failure",
		"api_auth_failure_realtime",
		"webmail_bruteforce",
		"ftp_auth_failure_realtime",
	}
	for _, check := range failureEvidence {
		if !blockableCheck(check, true) {
			t.Errorf("%s is not blockable with block_cpanel_logins=true; the switch no longer protects cPanel and webmail", check)
		}
		if blockableCheck(check, false) {
			t.Errorf("%s blocks with block_cpanel_logins=false; the switch is not being honoured", check)
		}
	}
}

// Checks that carry a confirmed attacker IP block regardless of the switch.
func TestAlwaysBlockableChecksIgnoreTheSwitch(t *testing.T) {
	for _, check := range []string{"wp_login_bruteforce", "mail_bruteforce", "ip_reputation", "ssh_login_unknown_ip"} {
		for _, blockCpanelLogins := range []bool{false, true} {
			if !blockableCheck(check, blockCpanelLogins) {
				t.Errorf("%s stopped being blockable (block_cpanel_logins=%v)", check, blockCpanelLogins)
			}
		}
	}
}

// An unknown check must not become blockable by accident.
func TestUnknownCheckIsNotBlockable(t *testing.T) {
	if blockableCheck("something_new_and_unclassified", true) {
		t.Error("an unregistered check was treated as block-eligible")
	}
}

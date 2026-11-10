package platform

import (
	"testing"
)

func TestLocalMTAIdentitiesIncludesCommonUnixMailUsers(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSUbuntu})
	for _, want := range []string{"mail", "mailnull", "postfix", "dovecot", "dovenull", "mailman"} {
		if !got.IsMTAUser(want) {
			t.Errorf("expected %q in MTA users; got %+v", want, got.Users)
		}
	}
}

func TestLocalMTAIdentitiesIncludesCommonProcessBasenames(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSUbuntu})
	for _, want := range []string{"postfix", "smtpd", "qmgr", "pickup", "cleanup", "dovecot", "imap-login", "pop3-login", "lmtp"} {
		if !got.IsMTAProcess(want) {
			t.Errorf("expected %q in MTA process basenames; got %+v", want, got.Processes)
		}
	}
}

func TestLocalMTAIdentitiesAddsEximOnCpanelHosts(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSAlma, Panel: PanelCPanel})
	if !got.IsMTAUser("exim") {
		t.Errorf("cPanel host missing exim user; got %+v", got.Users)
	}
	if !got.IsMTAProcess("exim") {
		t.Errorf("cPanel host missing exim process basename; got %+v", got.Processes)
	}
}

func TestIsMTAUserCaseSensitive(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSUbuntu})
	if got.IsMTAUser("MAIL") {
		t.Errorf("MTA user match must be case-sensitive (Linux usernames are)")
	}
}

func TestIsMTAProcessExactMatch(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSUbuntu})
	if got.IsMTAProcess("postfix-extra") {
		t.Errorf("MTA process match must be exact basename, not prefix")
	}
	if !got.IsMTAProcess("postfix") {
		t.Errorf("postfix exact match should succeed")
	}
}

// Stalwart runs its MTA as its own service user; without it every delivery
// it makes reads as a hosted process mailing out directly.
func TestLocalMTAIdentitiesIncludesStalwartOffCpanel(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSUbuntu})
	for _, want := range []string{"stalwart", "stalwart-mail"} {
		if !got.IsMTAUser(want) {
			t.Errorf("expected %q in MTA users; got %+v", want, got.Users)
		}
	}
}

// cPanel lets a customer pick an account name no system user holds, so a
// Stalwart name there would be an exemption anyone could sign up for.
func TestLocalMTAIdentitiesOmitsStalwartOnCpanel(t *testing.T) {
	got := LocalMTAIdentities(Info{OS: OSAlma, Panel: PanelCPanel})
	for _, name := range []string{"stalwart", "stalwart-mail"} {
		if got.IsMTAUser(name) {
			t.Errorf("cPanel host must not exempt %q; got %+v", name, got.Users)
		}
	}
}

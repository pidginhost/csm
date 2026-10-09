package antispam

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

const rspamdUID = 979

// goodFacts is a host that meets every precondition, shaped like the spike's
// scratch host.
func goodFacts() HostFacts {
	return HostFacts{
		CPanel:          true,
		MTAExim:         true,
		EximVersion:     CommandResult{Stdout: eximBV},
		EximOptions:     CommandResult{Stdout: "no_prdr_enable\nchunking_advertise_hosts = 198.51.100.1\n"},
		GeneratedConf:   "begin acl\nacl_smtp_data:\n  warn\n    condition = ${perl{spamd_is_available}}\n    spam = ${acl_m1}/defer_ok\n",
		LocalConf:       "@CONFIG@\n\n@DIRECTOREND@\n",
		NamedLists:      []CommandResult{{Stdout: "n\n"}, {Stdout: "n\n"}, {Stdout: "y\n"}},
		SpamdDisabled:   true,
		RspamdVersion:   CommandResult{Stdout: "Rspamd daemon version 4.2.1\n"},
		RspamadmVersion: CommandResult{Stdout: "Rspamadm 4.2.1\n"},
		Socket: SocketFacts{
			Socket: PathFacts{Path: DefaultSocket, UID: rspamdUID, Mode: fs.ModeSocket | 0o666},
			Parents: []PathFacts{
				{Path: "/", UID: 0, Mode: fs.ModeDir | 0o555},
				{Path: "/run", UID: 0, Mode: fs.ModeDir | 0o755},
				{Path: "/run/rspamd", UID: rspamdUID, Mode: fs.ModeDir | 0o755},
			},
			RspamdUID: rspamdUID,
			PeerUID:   rspamdUID,
		},
	}
}

func TestCheckHostAcceptsGoodHost(t *testing.T) {
	if got := CheckHost(goodFacts()); len(got) != 0 {
		t.Fatalf("good host reported %+v", got)
	}
}

func TestCheckHostProblems(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"not cpanel", func(f *HostFacts) { f.CPanel = false }, CodePlatform, Definite},
		{"exim -bV failed", func(f *HostFacts) { f.EximVersion = CommandResult{Err: boom} }, CodeEximVersion, Temporary},
		{"exim too old", func(f *HostFacts) { f.EximVersion.Stdout = strings.Replace(eximBV, "4.100.1", "4.96", 1) }, CodeEximVersion, Definite},
		{"no content scanning", func(f *HostFacts) { f.EximVersion.Stdout = strings.Replace(eximBV, "Content_Scanning ", "", 1) }, CodeEximVersion, Definite},
		{"spamd enabled", func(f *HostFacts) { f.SpamdDisabled = false }, CodeSpamAssassin, Definite},
		{"global enable", func(f *HostFacts) { f.GlobalEnable = true }, CodeGlobalEnable, Warning},
		{"socket stat error", func(f *HostFacts) { f.Socket.Err = boom }, CodeSocket, Temporary},
		{"socket missing", func(f *HostFacts) { f.Socket.Missing = true }, CodeSocket, Temporary},
		{"rspamd user unknown", func(f *HostFacts) { f.Socket.RspamdUID = -1 }, CodeSocket, Temporary},
		{"not a socket", func(f *HostFacts) { f.Socket.Socket.Mode = 0o666 }, CodeSocket, Definite},
		{"socket owned by tenant", func(f *HostFacts) { f.Socket.Socket.UID = 1001 }, CodeSocket, Definite},
		{"parent writable", func(f *HostFacts) { f.Socket.Parents[2].Mode = fs.ModeDir | 0o777 }, CodeSocket, Definite},
		{"parent owned by tenant", func(f *HostFacts) { f.Socket.Parents[2].UID = 1001 }, CodeSocket, Definite},
		{"parent symlink", func(f *HostFacts) { f.Socket.Parents[1].Mode = fs.ModeSymlink | 0o777 }, CodeSocket, Definite},
		{"parent ACL", func(f *HostFacts) { f.Socket.Parents[2].ExtACL = true }, CodeSocket, Definite},
		{"parents unchecked", func(f *HostFacts) { f.Socket.Parents = nil }, CodeSocket, Temporary},
		{"ping failed", func(f *HostFacts) { f.Socket.PingErr = boom }, CodeSocket, Temporary},
		{"listener is a tenant", func(f *HostFacts) { f.Socket.PeerUID = 1001 }, CodeSocket, Definite},
		{"rspamd version failed", func(f *HostFacts) { f.RspamdVersion.Err = boom }, CodeRspamdVersion, Temporary},
		{"rspamd too old", func(f *HostFacts) {
			f.RspamdVersion.Stdout, f.RspamadmVersion.Stdout = "Rspamd daemon version 2.7\n", "Rspamadm 2.7\n"
		}, CodeRspamdVersion, Definite},
		{"rspamadm differs", func(f *HostFacts) { f.RspamadmVersion.Stdout = "Rspamadm 4.1.0\n" }, CodeRspamdVersion, Definite},
		{"exim -bP failed", func(f *HostFacts) { f.EximOptions.Err = boom }, CodeEximOptions, Temporary},
		{"exim -bP incomplete", func(f *HostFacts) { f.EximOptions.Stdout = "no_prdr_enable\n" }, CodeEximOptions, Temporary},
		{"prdr on", func(f *HostFacts) {
			f.EximOptions.Stdout = "prdr_enable\nchunking_advertise_hosts = 198.51.100.1\n"
		}, CodeEximOptions, Definite},
		{"chunking on", func(f *HostFacts) {
			f.EximOptions.Stdout = "no_prdr_enable\nchunking_advertise_hosts = *\n"
		}, CodeEximOptions, Definite},
		{"generated unreadable", func(f *HostFacts) { f.GeneratedErr = boom }, CodeSpamScoreRules, Temporary},
		{"ungated spam deny", func(f *HostFacts) {
			f.GeneratedConf += "  deny condition = ${if >{$spam_score_int}{100}}\n"
		}, CodeSpamScoreRules, Definite},
		{"cutthrough", func(f *HostFacts) { f.GeneratedConf += "  accept control = cutthrough_delivery\n" }, CodeCutthrough, Definite},
		{"generated markers broken", func(f *HostFacts) { f.GeneratedConf += "# CSM-ANTISPAM BEGIN\n" }, CodeMarkers, Definite},
		{"local unreadable", func(f *HostFacts) { f.LocalErr = boom }, CodeForeignScanner, Temporary},
		{"foreign spamd_address", func(f *HostFacts) { f.LocalConf += "spamd_address = 127.0.0.1 783\n" }, CodeForeignScanner, Definite},
		{"local markers broken", func(f *HostFacts) { f.LocalConf += "# CSM-ANTISPAM END\n" }, CodeMarkers, Definite},
		{"named list probe failed", func(f *HostFacts) { f.NamedLists[1].Err = boom }, CodeNamedList, Temporary},
		{"named list undefined", func(f *HostFacts) {
			f.NamedLists[2] = CommandResult{Stdout: "Failed: unable to complete match against \"+cpanel_mail_netblocks\": NULL\n"}
		}, CodeNamedList, Definite},
		{"named lists incomplete", func(f *HostFacts) { f.NamedLists = f.NamedLists[:1] }, CodeNamedList, Temporary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 {
				t.Fatalf("got %d problems %+v, want exactly one %s", len(got), got, tc.code)
			}
			if got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Errorf("got %s/%d (%s), want %s/%d", got[0].Code, got[0].Severity, got[0].Detail, tc.code, tc.sev)
			}
		})
	}
}

package antispam

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

const (
	rspamdUID = 979
	// eximUID and eximGID are cPanel's mailnull user and mail group.
	eximUID, eximGID = 47, 12
)

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
			Socket: PathFacts{Path: DefaultSocket, UID: rspamdUID, GID: rspamdUID, Mode: fs.ModeSocket | 0o666},
			Parents: []PathFacts{
				{Path: "/", UID: 0, Mode: fs.ModeDir | 0o555},
				{Path: "/run", UID: 0, Mode: fs.ModeDir | 0o755},
				{Path: "/run/rspamd", UID: rspamdUID, GID: rspamdUID, Mode: fs.ModeDir | 0o755},
			},
			RspamdUID: rspamdUID,
			PeerUID:   rspamdUID,
			EximUID:   eximUID,
			EximGID:   eximGID,
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
		// A package upgrade replaces the two binaries one after the other.
		{"rspamadm differs", func(f *HostFacts) { f.RspamadmVersion.Stdout = "Rspamadm 4.1.0\n" }, CodeRspamdVersion, Temporary},
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
			f.NamedLists[2] = CommandResult{
				Stdout: "Failed: unable to complete match against \"+cpanel_mail_netblocks\": NULL\n",
				Stderr: "2026-10-09 08:12:11 unknown named host list \"+cpanel_mail_netblocks\"\n",
			}
		}, CodeNamedList, Definite},
		{"named list unexpected output", func(f *HostFacts) {
			f.NamedLists[2] = CommandResult{Stdout: "Failed: unable to complete match against \"+cpanel_mail_netblocks\": NULL\n"}
		}, CodeNamedList, Temporary},
		{"named list warning", func(f *HostFacts) { f.NamedLists[0].Stderr = "some warning\n" }, CodeNamedList, Temporary},
		{"spamddisable unreadable", func(f *HostFacts) {
			f.SpamdDisabled, f.SpamdDisabledErr = false, boom
		}, CodeSpamAssassin, Temporary},
		{"named lists incomplete", func(f *HostFacts) { f.NamedLists = f.NamedLists[:1] }, CodeNamedList, Temporary},
		// CSM's own probe runs as root, so only the mode bits show whether
		// Exim's mailnull user can reach the socket.
		{"exim user unknown", func(f *HostFacts) { f.Socket.EximUID = -1 }, CodeSocket, Temporary},
		{"socket closed to exim", func(f *HostFacts) { f.Socket.Socket.Mode = fs.ModeSocket | 0o660 }, CodeSocket, Definite},
		{"parent closed to exim", func(f *HostFacts) { f.Socket.Parents[2].Mode = fs.ModeDir | 0o750 }, CodeSocket, Definite},
		{"ungated router", func(f *HostFacts) {
			f.GeneratedConf += "begin routers\nfwd:\n  driver = redirect\n  condition = ${if >{$spam_score_int}{100}}\n"
		}, CodeSpamScoreRules, Definite},
		{"system filter spam rule", func(f *HostFacts) {
			f.SystemFilter = "if $spam_score_int is above 50 then\n  seen finish\nendif\n"
		}, CodeSpamScoreRules, Definite},
		{"system filter unreadable", func(f *HostFacts) { f.SystemFilterErr = boom }, CodeSpamScoreRules, Temporary},
		{"generated include", func(f *HostFacts) { f.GeneratedConf += ".include /etc/exim_extra.conf\n" }, CodeUnverifiable, Temporary},
		{"local include", func(f *HostFacts) { f.LocalConf += ".include_if_exists /etc/exim_extra.conf\n" }, CodeUnverifiable, Temporary},
		{"generated macro bomb", func(f *HostFacts) {
			f.GeneratedConf = "A = x\n" + strings.Repeat("A == A A\n", 26) + f.GeneratedConf
		}, CodeUnverifiable, Temporary},
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

func TestCheckHostUnreadableVersionsAreTemporary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
	}{
		{"exim", func(f *HostFacts) { f.EximVersion.Stdout = "" }, CodeEximVersion},
		{"rspamd", func(f *HostFacts) { f.RspamdVersion.Stdout = "" }, CodeRspamdVersion},
		{"rspamadm", func(f *HostFacts) { f.RspamadmVersion.Stdout = "" }, CodeRspamdVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != tc.code || got[0].Severity != Temporary {
				t.Fatalf("got %+v, want one temporary %s problem", got, tc.code)
			}
		})
	}
}

func TestCheckHostRetainsConfirmedConflicts(t *testing.T) {
	boom := errors.New("probe unavailable")
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
	}{
		{"prdr on and chunking unreadable", func(f *HostFacts) {
			f.EximOptions.Stdout = "prdr_enable\n"
		}, CodeEximOptions},
		{"chunking on and prdr unreadable", func(f *HostFacts) {
			f.EximOptions.Stdout = "chunking_advertise_hosts = *\n"
		}, CodeEximOptions},
		{"old daemon and failed admin probe", func(f *HostFacts) {
			f.RspamdVersion.Stdout = "Rspamd daemon version 2.7\n"
			f.RspamadmVersion.Err = boom
		}, CodeRspamdVersion},
		{"failed daemon probe and old admin", func(f *HostFacts) {
			f.RspamdVersion.Err = boom
			f.RspamadmVersion.Stdout = "Rspamadm 2.7\n"
		}, CodeRspamdVersion},
		{"unreadable daemon and old admin", func(f *HostFacts) {
			f.RspamdVersion.Stdout = ""
			f.RspamadmVersion.Stdout = "Rspamadm 2.7\n"
		}, CodeRspamdVersion},
		{"old daemon and unreadable admin", func(f *HostFacts) {
			f.RspamdVersion.Stdout = "Rspamd daemon version 2.7\n"
			f.RspamadmVersion.Stdout = ""
		}, CodeRspamdVersion},
		{"unknown service user and socket symlink", func(f *HostFacts) {
			f.Socket.RspamdUID = -1
			f.Socket.Socket.Mode = fs.ModeSymlink | 0o777
		}, CodeSocket},
		{"unknown service user and writable parent", func(f *HostFacts) {
			f.Socket.RspamdUID = -1
			f.Socket.Parents[2].Mode = fs.ModeDir | 0o777
		}, CodeSocket},
		{"unknown service user and parent ACL", func(f *HostFacts) {
			f.Socket.RspamdUID = -1
			f.Socket.Parents[2].ExtACL = true
		}, CodeSocket},
		{"missing socket and writable parent", func(f *HostFacts) {
			f.Socket.Missing = true
			f.Socket.Parents[2].Mode = fs.ModeDir | 0o777
		}, CodeSocket},
		{"socket stat failure and writable parent", func(f *HostFacts) {
			f.Socket.Err = boom
			f.Socket.Parents[2].Mode = fs.ModeDir | 0o777
		}, CodeSocket},
		{"untrusted peer and failed ping", func(f *HostFacts) {
			f.Socket.PeerUID = 1001
			f.Socket.PingErr = boom
		}, CodeSocket},
		{"incomplete named lists and undefined list", func(f *HostFacts) {
			f.NamedLists = []CommandResult{{
				Stdout: "Failed: unable to complete match against \"+local_domains\": NULL\n",
				Stderr: "2026-10-09 08:12:11 unknown named domain list \"+local_domains\"\n",
			}}
		}, CodeNamedList},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 2 {
				t.Fatalf("got %+v, want one temporary and one definite %s problem", got, tc.code)
			}
			counts := make(map[Severity]int)
			for _, p := range got {
				if p.Code != tc.code {
					t.Errorf("got code %s, want %s", p.Code, tc.code)
				}
				counts[p.Severity]++
			}
			if counts[Temporary] != 1 || counts[Definite] != 1 {
				t.Errorf("got %+v, want one temporary and one definite problem", got)
			}
		})
	}
}

func TestCheckHostUnknownPeerIsTemporary(t *testing.T) {
	f := goodFacts()
	f.Socket.PeerUID = -1
	got := CheckHost(f)
	if len(got) != 1 || got[0].Code != CodeSocket || got[0].Severity != Temporary {
		t.Fatalf("got %+v, want one temporary socket problem", got)
	}
}

func TestCheckHostIgnoresFailedVersionOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
	}{
		{"exim", func(f *HostFacts) {
			f.EximVersion = CommandResult{Stdout: "Exim version 4.96\n", Err: errors.New("probe unavailable")}
		}, CodeEximVersion},
		{"rspamd", func(f *HostFacts) {
			f.RspamdVersion = CommandResult{Stdout: "Rspamd daemon version 2.7\n", Err: errors.New("probe unavailable")}
		}, CodeRspamdVersion},
		{"rspamadm", func(f *HostFacts) {
			f.RspamadmVersion = CommandResult{Stdout: "Rspamadm 2.7\n", Err: errors.New("probe unavailable")}
		}, CodeRspamdVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != tc.code || got[0].Severity != Temporary {
				t.Fatalf("got %+v, want one temporary %s problem", got, tc.code)
			}
		})
	}
}

func TestCheckHostRejectsDuplicateLocalBlocks(t *testing.T) {
	hooks, err := RenderExim(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	f := goodFacts()
	f.LocalConf = "@CONFIG@\n" + hooks.Config + "@DIRECTOREND@\n"
	f.GeneratedConf = hooks.Config + "begin acl\nacl_smtp_rcpt:\n" + hooks.RCPT + "acl_smtp_data:\n" + hooks.Scan + hooks.Post
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("valid installed hooks reported %+v", got)
	}
	f.LocalConf = "@CONFIG@\n" + hooks.Config + hooks.Config + "@DIRECTOREND@\n"
	got := CheckHost(f)
	if len(got) != 1 || got[0].Code != CodeMarkers || got[0].Severity != Definite {
		t.Fatalf("got %+v, want one definite local-marker problem", got)
	}
}

func TestCheckHostDiagnosticsDoNotExposeProbeOutput(t *testing.T) {
	const diagnostic = "untrusted diagnostic text"
	boom := errors.New(diagnostic + "\n" + strings.Repeat("diagnostic ", 4096))
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"exim version", func(f *HostFacts) { f.EximVersion.Err = boom }, CodeEximVersion, Temporary},
		{"exim options", func(f *HostFacts) { f.EximOptions.Err = boom }, CodeEximOptions, Temporary},
		{"socket stat", func(f *HostFacts) { f.Socket.Err = boom }, CodeSocket, Temporary},
		{"socket ping", func(f *HostFacts) { f.Socket.PingErr = boom }, CodeSocket, Temporary},
		{"generated config", func(f *HostFacts) { f.GeneratedErr = boom }, CodeSpamScoreRules, Temporary},
		{"local config", func(f *HostFacts) { f.LocalErr = boom }, CodeForeignScanner, Temporary},
		{"named list command", func(f *HostFacts) { f.NamedLists[0].Err = boom }, CodeNamedList, Temporary},
		{"named list stdout", func(f *HostFacts) { f.NamedLists[0].Stdout = diagnostic + "\n" }, CodeNamedList, Temporary},
		{"named list stderr", func(f *HostFacts) {
			f.NamedLists[0] = CommandResult{Stderr: diagnostic + "\n"}
		}, CodeNamedList, Temporary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Fatalf("got %+v, want one %s/%d problem", got, tc.code, tc.sev)
			}
			if got[0].Detail == "" || len(got[0].Detail) > 512 || strings.Contains(got[0].Detail, diagnostic) {
				t.Error("finding must contain a bounded explanation without raw probe diagnostics")
			}
		})
	}
}

func TestCheckHostAcceptsSocketThroughEximGroup(t *testing.T) {
	f := goodFacts()
	f.Socket.Socket.Mode = fs.ModeSocket | 0o660
	f.Socket.Socket.GID = eximGID
	f.Socket.Parents[2].Mode = fs.ModeDir | 0o750
	f.Socket.Parents[2].GID = eximGID
	if got := CheckHost(f); len(got) != 0 {
		t.Fatalf("socket reachable through Exim's group reported %+v", got)
	}
}

func TestCheckHostSocketACLAccessIsTemporary(t *testing.T) {
	for _, mode := range []fs.FileMode{0o660, 0o666} {
		f := goodFacts()
		f.Socket.Socket.Mode = fs.ModeSocket | mode
		f.Socket.Socket.ExtACL = true
		got := CheckHost(f)
		if len(got) != 1 || got[0].Code != CodeSocket || got[0].Severity != Temporary {
			t.Fatalf("socket mode %o with unread ACL: got %+v, want one temporary socket problem", mode, got)
		}
	}
}

func TestCheckHostRetainsConflictsBeforeUnverifiableMacros(t *testing.T) {
	bomb := "A = x\n" + strings.Repeat("A == A A\n", 26)
	for _, tc := range []struct {
		name, code string
		mutate     func(*HostFacts)
	}{
		{"spam score", CodeSpamScoreRules, func(f *HostFacts) {
			f.GeneratedConf += "deny condition = ${if >{$spam_score_int}{100}}\n" + bomb
		}},
		{"cutthrough", CodeCutthrough, func(f *HostFacts) {
			f.GeneratedConf += "accept control = cutthrough_delivery\n" + bomb
		}},
		{"scanner", CodeForeignScanner, func(f *HostFacts) {
			f.LocalConf += "spamd_address = /run/rspamd/operator.sock\n" + bomb
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 2 {
				t.Fatalf("got %+v, want a confirmed conflict and an unverifiable problem", got)
			}
			counts := make(map[string]int)
			for _, p := range got {
				if p.Code == tc.code && p.Severity == Definite || p.Code == CodeUnverifiable && p.Severity == Temporary {
					counts[p.Code]++
				} else {
					t.Errorf("unexpected problem %+v", p)
				}
			}
			if counts[tc.code] != 1 || counts[CodeUnverifiable] != 1 {
				t.Fatalf("got %+v, want one of each problem", got)
			}
		})
	}
}

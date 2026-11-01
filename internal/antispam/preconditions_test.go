package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// eximSettings is `exim -bP` for EximSettingNames on the spike's host.
const eximSettings = "message_size_limit = 50M\nlog_file_path = /var/log/exim_%slog\nexim_user = mailnull\nexim_group = mail\nsystem_filter = /etc/cpanel_exim_system_filter\n"

const (
	rspamdUID = 979
	// eximUID and eximGID are cPanel's mailnull user and mail group.
	eximUID, eximGID = 47, 12
)

// goodFacts is a host that meets every precondition, shaped like the spike's
// scratch host.
func goodFacts() HostFacts {
	return HostFacts{
		Stack:           StackExim,
		EximVersion:     CommandResult{Stdout: eximBV},
		EximOptions:     CommandResult{Stdout: "no_prdr_enable\nchunking_advertise_hosts = 198.51.100.1\n"},
		EximSettings:    CommandResult{Stdout: eximSettings},
		RspamdOptions:   CommandResult{Stdout: `{"max_message": 62914560, "task_timeout": 8.0}`},
		MonitoredLog:    "/var/log/exim_mainlog",
		RspamdService:   CommandResult{Stdout: "User=_rspamd\nLoadState=loaded\nCanReload=yes\n"},
		EximService:     CommandResult{Stdout: "User=\nLoadState=loaded\nCanReload=yes\n"},
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
		Targets: goodTargets(),
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
		{"stack none", func(f *HostFacts) { f.Stack, f.Record = StackNone, RecordFacts{Missing: true} }, CodePlatform, Definite},
		{"exim -bV failed", func(f *HostFacts) { f.EximVersion = CommandResult{Err: boom} }, CodeEximVersion, Temporary},
		{"exim too old", func(f *HostFacts) { f.EximVersion.Stdout = strings.Replace(eximBV, "4.100.1", "4.96", 1) }, CodeEximVersion, Definite},
		{"no content scanning", func(f *HostFacts) { f.EximVersion.Stdout = strings.Replace(eximBV, "Content_Scanning ", "", 1) }, CodeEximVersion, Definite},
		{"spamd enabled", func(f *HostFacts) { f.SpamdDisabled = false }, CodeSpamAssassin, Definite},
		{"global enable", func(f *HostFacts) { f.GlobalEnable = true }, CodeGlobalEnable, Warning},
		{"global enable unreadable", func(f *HostFacts) { f.GlobalEnableErr = boom }, CodeGlobalEnable, Warning},
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

// Without the rspamd uid, CSM cannot prove which non-root uid on the socket
// path is rspamd's, but two different non-root uids cannot both be.
func TestCheckHostSocketOwnersWithUnknownRspamdUser(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*SocketFacts)
		sev    Severity
		detail string
	}{
		{"one owner", func(*SocketFacts) {}, Temporary, "uid 979"},
		{"tenant directory", func(s *SocketFacts) { s.Parents[2].UID = 1001 }, Definite, "[979 1001]"},
		{"tenant listener", func(s *SocketFacts) { s.PeerUID = 1001 }, Definite, "[979 1001]"},
		{"tenant socket", func(s *SocketFacts) { s.Socket.UID = 1001 }, Definite, "[979 1001]"},
		{"root only", func(s *SocketFacts) { s.Socket.UID, s.Parents[2].UID, s.PeerUID = 0, 0, 0 }, Temporary, "service user is unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			f.Socket.RspamdUID = -1
			tc.mutate(&f.Socket)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != CodeSocket || got[0].Severity != tc.sev || !strings.Contains(got[0].Detail, tc.detail) {
				t.Fatalf("got %+v, want one socket problem of severity %d naming %q", got, tc.sev, tc.detail)
			}
		})
	}
}

func TestCheckHostSocketOwnerDiagnosticStaysBounded(t *testing.T) {
	f := goodFacts()
	f.Socket.RspamdUID = -1
	for i := range 128 {
		f.Socket.Parents = append(f.Socket.Parents, PathFacts{
			Path: fmt.Sprintf("/run/socket-link-%d", i),
			UID:  1000 + i,
			Mode: fs.ModeDir | 0o755,
		})
	}
	got := CheckHost(f)
	if len(got) != 1 || got[0].Code != CodeSocket || got[0].Severity != Definite {
		t.Fatalf("got %+v, want one definite socket ownership problem", got)
	}
	if len(got[0].Detail) > 512 {
		t.Fatalf("socket ownership diagnostic is %d bytes; want at most 512", len(got[0].Detail))
	}
	if !strings.Contains(got[0].Detail, "[979 1000]") {
		t.Fatalf("diagnostic %q does not name two conflicting owners", got[0].Detail)
	}

	f.Socket.Parents[len(f.Socket.Parents)-1].Mode = fs.ModeDir | 0o777
	got = CheckHost(f)
	if len(got) != 2 || got[0].Code != CodeSocket || got[0].Severity != Definite ||
		!strings.Contains(got[0].Detail, "writable by group or others") ||
		got[1].Code != CodeSocket || got[1].Severity != Definite || len(got[1].Detail) > 512 {
		t.Fatalf("got %+v, want both the later directory conflict and bounded ownership evidence", got)
	}
}

func TestCheckHostSocketParentOwnersSurviveUnavailableSocket(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*SocketFacts)
	}{
		{"missing", func(s *SocketFacts) { s.Missing = true }},
		{"stat failed", func(s *SocketFacts) { s.Err = errors.New("stat failed") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			f.Socket.RspamdUID = -1
			f.Socket.Parents[1].UID = 1001
			f.Socket.Socket.UID, f.Socket.PeerUID = 1002, 1003
			tc.mutate(&f.Socket)
			got := CheckHost(f)
			if len(got) != 2 || got[0].Code != CodeSocket || got[0].Severity != Temporary ||
				got[1].Code != CodeSocket || got[1].Severity != Definite ||
				!strings.Contains(got[1].Detail, "[979 1001]") {
				t.Fatalf("got %+v, want a temporary socket failure and confirmed parent ownership conflict", got)
			}
		})
	}
}

// Two different exim -bP commands fail with two different diagnostics.
func TestCheckHostNamesEachEximOptionQuery(t *testing.T) {
	f := goodFacts()
	f.EximOptions.Err = errors.New("exit status 1")
	f.EximSettings.Err = errors.New("exit status 1")
	var details []string
	for _, p := range CheckHost(f) {
		if p.Code == CodeEximOptions {
			details = append(details, p.Detail)
		}
	}
	if len(details) != 2 || details[0] == details[1] {
		t.Fatalf("exim -bP failures: %q", details)
	}
}

// postfixFacts is a Postfix host whose milter reaches rspamd's proxy
// worker. Its Exim facts are unset and its targets are the Postfix list, as
// the collector leaves them there.
func postfixFacts() HostFacts {
	f := goodFacts()
	f.Stack = StackPostfix
	f.EximVersion, f.EximOptions, f.EximSettings, f.EximService = CommandResult{}, CommandResult{}, CommandResult{}, CommandResult{}
	f.GeneratedConf, f.LocalConf, f.NamedLists, f.SpamdDisabled, f.MonitoredLog = "", "", nil, false, ""
	f.Socket.EximUID, f.Socket.EximGID = -1, -1
	f.Postconf = CommandResult{Stdout: postconfOut("inet:127.0.0.1:11332", "52428800")}
	f.PostfixMaster = CommandResult{Stdout: "smtp/inet/command = smtpd\nsmtp/inet/chroot = n\n"}
	f.PostfixService = CommandResult{Stdout: "LoadState=loaded\nActiveState=active\n"}
	f.RspamdWorkers = CommandResult{Stdout: proxyWorkers}
	f.Targets = stackTargets(StackPostfix)
	return f
}

func TestCheckHostPostfix(t *testing.T) {
	if got := CheckHost(postfixFacts()); len(got) != 0 {
		t.Fatalf("wired Postfix host reported %+v", got)
	}
	// Only CSM, as root, uses the scan socket there; Exim's access is moot
	// even when an Exim user is known.
	private := postfixFacts()
	private.Socket.EximUID, private.Socket.EximGID = eximUID, eximGID
	private.Socket.Socket.Mode = fs.ModeSocket | 0o600
	private.Socket.Parents[2].Mode = fs.ModeDir | 0o700
	if got := CheckHost(private); len(got) != 0 {
		t.Fatalf("Postfix host with a private scan socket reported %+v", got)
	}

	boom := errors.New("boom")
	// Debian's layout: smtpd chrooted into the queue directory, rspamd's
	// proxy listening inside it.
	const unixProxy = `{"rspamd_proxy": {"bind_socket": "/var/spool/postfix/rspamd/milter.sock mode=0666", "milter": true}}`
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
	}{
		{"chrooted unix milter", func(f *HostFacts) {
			f.Postconf.Stdout = postconfOut("unix:/rspamd/milter.sock", "52428800")
			f.PostfixMaster.Stdout = "smtp/inet/command = postscreen\nsmtp/inet/chroot = y\nsmtpd/pass/chroot = y\n"
			f.RspamdWorkers.Stdout = unixProxy
		}},
		{"relative unix milter", func(f *HostFacts) {
			f.Postconf.Stdout = postconfOut("unix:rspamd/milter.sock", "52428800")
			f.PostfixMaster = CommandResult{Err: boom}
			f.RspamdWorkers.Stdout = unixProxy
		}},
		{"inet milter, chroot unknown", func(f *HostFacts) { f.PostfixMaster = CommandResult{Err: boom} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := postfixFacts()
			tc.mutate(&f)
			if got := CheckHost(f); len(got) != 0 {
				t.Fatalf("wired Postfix host reported %+v", got)
			}
		})
	}

	const unwired = "postfix does not pass mail to rspamd's proxy worker"
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
		detail string
	}{
		{"milter elsewhere", func(f *HostFacts) { f.Postconf.Stdout = postconfOut("inet:127.0.0.1:8891", "52428800") }, CodeMilter, Definite, unwired},
		{"no milters", func(f *HostFacts) { f.Postconf.Stdout = postconfOut("", "52428800") }, CodeMilter, Definite, unwired},
		// Postfix reads an absolute path as written when smtpd is not chrooted.
		{"unix milter, smtpd not chrooted", func(f *HostFacts) {
			f.Postconf.Stdout = postconfOut("unix:/rspamd/milter.sock", "52428800")
			f.RspamdWorkers.Stdout = unixProxy
		}, CodeMilter, Definite, unwired},
		{"unix milter, chroot unknown", func(f *HostFacts) {
			f.Postconf.Stdout = postconfOut("unix:/rspamd/milter.sock", "52428800")
			f.PostfixMaster = CommandResult{Err: boom}
			f.RspamdWorkers.Stdout = unixProxy
		}, CodeMilter, Temporary, "cannot tell whether postfix smtpd runs chrooted"},
		{"proxy is no milter", func(f *HostFacts) {
			f.RspamdWorkers.Stdout = `{"rspamd_proxy": {"bind_socket": "localhost:11332"}}`
		}, CodeMilter, Definite, unwired},
		{"postconf failed", func(f *HostFacts) { f.Postconf.Err = boom }, CodeMilter, Temporary, ""},
		{"postconf unreadable", func(f *HostFacts) { f.Postconf.Stdout = "inet:127.0.0.1:11332\n" }, CodeMilter, Temporary, ""},
		{"queue directory unreadable", func(f *HostFacts) {
			f.Postconf.Stdout = "unix:rspamd/milter.sock\naccept\n52428800\n\n3.7.11\n"
		}, CodeMilter, Temporary, ""},
		{"worker dump failed", func(f *HostFacts) { f.RspamdWorkers.Err = boom }, CodeMilter, Temporary, ""},
		{"worker dump unreadable", func(f *HostFacts) { f.RspamdWorkers.Stdout = "Section worker NOT FOUND\n" }, CodeMilter, Temporary, ""},
		{"postfix query failed", func(f *HostFacts) { f.PostfixService.Err = boom }, CodeSystemd, Temporary, ""},
		{"postfix not installed", func(f *HostFacts) {
			f.PostfixService.Stdout = "LoadState=not-found\nActiveState=inactive\n"
		}, CodeSystemd, Temporary, ""},
		{"postfix not active", func(f *HostFacts) {
			f.PostfixService.Stdout = "LoadState=loaded\nActiveState=failed\n"
		}, CodeSystemd, Temporary, ""},
		{"postfix state unknown", func(f *HostFacts) { f.PostfixService.Stdout = "LoadState=loaded\n" }, CodeSystemd, Temporary, ""},
		{"rspamd cannot reload", func(f *HostFacts) {
			f.RspamdService.Stdout = "User=_rspamd\nLoadState=loaded\nCanReload=no\n"
		}, CodeSystemd, Definite, ""},
		{"socket missing", func(f *HostFacts) { f.Socket.Missing = true }, CodeSocket, Temporary, ""},
		{"socket owned by tenant", func(f *HostFacts) { f.Socket.Socket.UID = 1001 }, CodeSocket, Definite, ""},
		{"rspamd too old", func(f *HostFacts) {
			f.RspamdVersion.Stdout, f.RspamadmVersion.Stdout = "Rspamd daemon version 2.7\n", "Rspamadm 2.7\n"
		}, CodeRspamdVersion, Definite, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := postfixFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 || got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Fatalf("got %+v, want exactly one %s/%d problem", got, tc.code, tc.sev)
			}
			if tc.detail != "" && got[0].Detail != tc.detail {
				t.Errorf("detail %q, want %q", got[0].Detail, tc.detail)
			}
		})
	}

	none := goodFacts()
	none.Stack, none.Record = StackNone, RecordFacts{Missing: true}
	got := CheckHost(none)
	if len(got) != 1 || got[0].Code != CodePlatform || got[0].Severity != Definite ||
		got[0].Detail != "needs a cPanel host running Exim, or a Postfix host" {
		t.Fatalf("host without a supported stack: got %+v", got)
	}
}

// A host without a supported mail stack is refused with one problem; the
// collector gathered no Exim facts there, so no Exim check runs. With CSM's
// integration installed it is a Postfix host whose MTA is down or
// restarting (a cPanel host always runs Exim), so the problem is temporary
// and the integration stays.
func TestCheckHostUnknownStack(t *testing.T) {
	bare := HostFacts{Stack: StackNone, Record: RecordFacts{Missing: true}}
	got := CheckHost(bare)
	if len(got) != 1 || got[0].Code != CodePlatform || got[0].Severity != Definite ||
		got[0].Detail != "needs a cPanel host running Exim, or a Postfix host" {
		t.Fatalf("host without a supported stack: got %+v", got)
	}
	installed := bare
	installed.Record = RecordFacts{Content: string(EncodeRecord(""))}
	got = CheckHost(installed)
	if len(got) != 1 || got[0].Code != CodePlatform || got[0].Severity != Temporary ||
		got[0].Detail != "CSM cannot tell which mail server this host runs, for example while Postfix restarts" {
		t.Fatalf("installed host without a detected stack: got %+v", got)
	}
}

// CSM reads a Postfix host's scan records from rspamd's log file. rspamd
// logging elsewhere leaves the integration working without them, so CSM
// warns instead of refusing.
func TestCheckHostPostfixRspamdLog(t *testing.T) {
	for _, tc := range []struct {
		log    LogFacts
		detail string
	}{
		{LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log"}, ""},
		// A log CSM could not inspect is still read; the daemon reports one
		// it cannot open.
		{LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log", Err: errors.New("permission denied")}, ""},
		{LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log", Missing: true},
			"rspamd's log file /var/log/rspamd/rspamd.log does not exist; CSM reads scan records from it once rspamd writes it"},
		{LogFacts{Type: "file", Path: "rspamd.log", Err: errors.New("rspamd's log file is not an absolute path")},
			"rspamd's log file is not an absolute path; CSM reads scan records only from one"},
		// Unreadable logging settings are reported where they matter.
		{LogFacts{Err: errors.New("rspamd's logging settings are not readable")}, ""},
		{LogFacts{Type: "console"}, "rspamd logs to the journal; CSM reads scan records from a file log"},
		{LogFacts{Type: "syslog"}, "rspamd logs to syslog; CSM reads scan records from a file log"},
		{LogFacts{Type: "pipe"}, `rspamd's log type "pipe" is not a file; CSM reads scan records from a file log`},
	} {
		t.Run(tc.log.Type+" "+tc.log.Path, func(t *testing.T) {
			f := postfixFacts()
			f.RspamdLog = tc.log
			got := CheckHost(f)
			if tc.detail == "" {
				if len(got) != 0 {
					t.Fatalf("got %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0] != (Problem{Code: CodeRspamdLog, Severity: Warning, Detail: tc.detail}) {
				t.Fatalf("got %+v, want one %s warning %q", got, CodeRspamdLog, tc.detail)
			}
		})
	}
	// The Exim backend reads its own markers from Exim's log.
	exim := goodFacts()
	exim.RspamdLog = LogFacts{Type: "console"}
	if got := CheckHost(exim); len(got) != 0 {
		t.Fatalf("Exim host reported %+v", got)
	}
}

// rspamd passes a message over max_message unscanned; that is the host's
// choice, so CSM warns instead of refusing.
func TestCheckHostPostfixMessageSize(t *testing.T) {
	for _, tc := range []struct {
		name, limit string
		options     CommandResult
		sev         Severity
		want        int
	}{
		{"max_message below limit", "52428800", CommandResult{Stdout: `{"max_message": 20971520}`}, Warning, 1},
		{"postfix unlimited", "0", CommandResult{Stdout: `{"max_message": 52428800}`}, Warning, 1},
		{"equal", "52428800", CommandResult{Stdout: `{"max_message": 52428800}`}, 0, 0},
		{"rspamd default", "10240000", CommandResult{Stdout: `{}`}, 0, 0},
		{"rspamd unlimited", "0", CommandResult{Stdout: `{"max_message": 0}`}, 0, 0},
		{"options failed", "52428800", CommandResult{Err: errors.New("boom")}, Temporary, 1},
		{"options unreadable", "52428800", CommandResult{Stdout: `{"max_message": "big"}`}, Temporary, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := postfixFacts()
			f.Postconf.Stdout = postconfOut("inet:127.0.0.1:11332", tc.limit)
			f.RspamdOptions = tc.options
			got := CheckHost(f)
			if len(got) != tc.want || tc.want == 1 && (got[0].Code != CodeMessageSize || got[0].Severity != tc.sev) {
				t.Fatalf("got %+v, want %d %s problem of severity %d", got, tc.want, CodeMessageSize, tc.sev)
			}
		})
	}
}

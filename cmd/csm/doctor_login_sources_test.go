package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

func TestLoginSourcesDoctorCheck(t *testing.T) {
	file := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name          string
		syslogJournal bool
		source, path  string
		units         []string
		mta           platform.MTAKind
		mail          string
		fileServices  string
		warn          bool
		fix           string
	}{
		{"all journal", true, "journal", file, []string{"postfix"}, platform.MTAPostfix, "journal", "", false, ""},
		{"syslog files", false, "journal", file, []string{"postfix"}, platform.MTAPostfix, "journal", "SSH and FTP", true, "journald"},
		{"explicit mail file", true, "file", file, nil, platform.MTAPostfix, "syslog file", "mail", true, "mail_logs.source"},
		{"auto file without units", false, "auto", file, nil, platform.MTAPostfix, "syslog file", "SSH, FTP and mail", true, "mail_logs.source"},
		{"auto missing file fallback", false, "auto", missing, []string{"postfix"}, platform.MTAPostfix, "journal", "SSH and FTP", true, "journald"},
		{"missing file", true, "file", missing, nil, platform.MTAPostfix, "unavailable", "", true, "mail_logs.file"},
		{"missing file without fallback", true, "auto", missing, nil, platform.MTAPostfix, "unavailable", "", true, "mail_logs.units"},
		{"journal without units", true, "journal", file, nil, platform.MTAPostfix, "unavailable", "", true, "mail_logs.units"},
		{"stalwart with journal setting", true, "journal", missing, nil, platform.MTAStalwart, "Stalwart service log", "", false, ""},
		{"stalwart with file setting", true, "file", missing, nil, platform.MTAStalwart, "Stalwart service log", "", false, ""},
		{"stalwart without journald", false, "auto", missing, nil, platform.MTAStalwart, "Stalwart service log", "SSH and FTP", true, "journald"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{MailLogs: config.MailLogsConfig{Source: tc.source, File: tc.path, Units: tc.units}}
			c := loginSourcesDoctorCheck(tc.syslogJournal, cfg, tc.mta, "", nil)
			status := "ok"
			if tc.warn || tc.mail == "journal" && !maillog.JournalSupported() {
				status = "warn"
			}
			if c.Name != "login sources" || c.Status != status || !strings.Contains(c.Message, "mail: "+tc.mail) ||
				(tc.fix != "" && !strings.Contains(c.Fix, tc.fix)) {
				t.Fatalf("check = %+v", c)
			}
			syslogSource := "syslog files"
			if tc.syslogJournal {
				syslogSource = "journal"
			}
			if !strings.Contains(c.Message, "SSH and FTP: "+syslogSource) || !strings.Contains(c.Message, "Watcher health reports source availability") {
				t.Fatalf("source selection or availability misreported: %+v", c)
			}
			if tc.fileServices != "" {
				if !strings.Contains(c.Message, tc.fileServices+" syslog lines only alert; they never block or count as customer logins") {
					t.Fatalf("wrong file trust warning: %+v", c)
				}
			} else if strings.Contains(c.Message, "only alert") {
				t.Fatalf("non-file source reported as alert-only: %+v", c)
			}
			if status == "ok" && c.Fix != "" {
				t.Fatalf("ok row carries a fix: %+v", c)
			}
			if tc.mail == "journal" && !maillog.JournalSupported() &&
				(!strings.Contains(c.Message, "unsupported by this build") || !strings.Contains(c.Fix, "build with journal support")) {
				t.Fatalf("unsupported journal not reported: %+v", c)
			}
		})
	}
}

func TestLoginSourcesDoesNotCallStalwartAJournal(t *testing.T) {
	c := loginSourcesDoctorCheck(true, &config.Config{}, platform.MTAStalwart, "", nil)
	if !strings.Contains(c.Message, "mail: Stalwart service log") || c.Status != "ok" || c.Fix != "" {
		t.Fatalf("Stalwart's own log is misreported: %+v", c)
	}
}

func TestLoginSourcesUsesPlatformFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "maillog")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{MailLogs: config.MailLogsConfig{Source: "auto"}}
	c := loginSourcesDoctorCheck(false, cfg, platform.MTAPostfix, file, nil)
	if c.Status != "warn" || !strings.Contains(c.Message, "mail: syslog file") || strings.Contains(c.Message, "unavailable") {
		t.Fatalf("platform file ignored: %+v", c)
	}
}

// Without DontResolve pure-ftpd logs client host names, so FTP failures only
// alert; the check names each configuration source to fix.
func TestLoginSourcesDoctorCheckFTPHostNames(t *testing.T) {
	c := loginSourcesDoctorCheck(true, &config.Config{}, platform.MTAStalwart, "", []string{"/etc/pure-ftpd.conf"})
	if c.Status != "warn" || !strings.Contains(c.Message, "FTP failures only alert while pure-ftpd logs client host names") ||
		!strings.Contains(c.Fix, "set DontResolve yes in /etc/pure-ftpd.conf and restart pure-ftpd") {
		t.Fatalf("check = %+v", c)
	}
	c = loginSourcesDoctorCheck(true, &config.Config{}, platform.MTAStalwart, "", nil)
	if c.Status != "ok" || strings.Contains(c.Message, "pure-ftpd") {
		t.Fatalf("check without the gap = %+v", c)
	}
}

func TestLoginSourcesDoctorDebianDontResolve(t *testing.T) {
	c := loginSourcesDoctorCheck(true, &config.Config{}, platform.MTAStalwart, "", []string{"/etc/pure-ftpd/conf/DontResolve"})
	if c.Status != "warn" || !strings.Contains(c.Fix, "write yes to /etc/pure-ftpd/conf/DontResolve") || strings.Contains(c.Fix, "set DontResolve yes in /etc/pure-ftpd/conf/DontResolve") {
		t.Fatalf("doctor must give the wrapper's value-only syntax: %+v", c)
	}
}

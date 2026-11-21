package main

import (
	"strings"
	"testing"
)

// Doctor says where SSH, mail and FTP logins come from: entries a service
// wrote to the journal can block; lines read from a syslog file only alert.
func TestLoginSourcesDoctorCheck(t *testing.T) {
	for _, tc := range []struct {
		name                string
		syslogJournal, mail bool
		status              string
		says, fix, saysNot  string
	}{
		{"all from the journal", true, true, "ok", "journal", "", "alert"},
		{"syslog files", false, true, "warn", "SSH and FTP", "journald", "mail"},
		{"mail file", true, false, "warn", "mail", "mail_logs.source", "SSH"},
		{"all files", false, false, "warn", "SSH, mail and FTP", "journald", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := loginSourcesDoctorCheck(tc.syslogJournal, tc.mail)
			if c.Name != "login sources" || c.Status != tc.status || !strings.Contains(c.Message, tc.says) ||
				(tc.fix != "" && !strings.Contains(c.Fix, tc.fix)) || (tc.saysNot != "" && strings.Contains(c.Message, tc.saysNot)) {
				t.Fatalf("check = %+v", c)
			}
			if tc.status == "ok" && c.Fix != "" {
				t.Fatalf("ok row carries a fix: %+v", c)
			}
		})
	}
}

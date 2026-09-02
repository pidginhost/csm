package platform

import "testing"

// cronie (RHEL family, cPanel) keeps per-user crontabs directly under
// /var/spool/cron; Debian's cron keeps them one level deeper. Every
// crontab detector has to ask the platform, or it is blind on Debian/Ubuntu.
func TestInfoCronSpoolDir(t *testing.T) {
	cases := map[OSFamily]string{
		OSUbuntu:     "/var/spool/cron/crontabs",
		OSDebian:     "/var/spool/cron/crontabs",
		OSAlma:       "/var/spool/cron",
		OSCloudLinux: "/var/spool/cron",
		OSUnknown:    "/var/spool/cron",
	}
	for os, want := range cases {
		if got := (Info{OS: os}).CronSpoolDir(); got != want {
			t.Errorf("CronSpoolDir(%q) = %q, want %q", os, got, want)
		}
	}
}

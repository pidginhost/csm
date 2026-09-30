package checks

import (
	"strings"
	"testing"
)

func FuzzCronScheduleFingerprint(f *testing.F) {
	for _, command := range []string{"/usr/bin/true", "/usr/bin/cat%input", "x\x00y", "x\r", "x\n17 3 ~ * * root job"} {
		f.Add(command)
	}
	f.Fuzz(func(t *testing.T, command string) {
		before := "17 3 * * * root " + command + "\n"
		after := "42 0 * * * root " + command + "\n"
		first := cronScheduleFingerprint("/etc/cron.d/job", []byte(before))
		second := cronScheduleFingerprint("/etc/cron.d/job", []byte(after))
		if first != second {
			t.Fatal("moving the time changed the execution fingerprint")
		}
		if first != "" {
			changedCommand := "42 0 * * * root different " + command + "\n"
			if cronScheduleUnchanged(first, cronScheduleFingerprint("/etc/cron.d/job", []byte(changedCommand))) {
				t.Fatal("a changed command retained the execution fingerprint")
			}
			// Randomized days in any entry are chosen again at reload.
			randomCalendar := after + "* * 1~28 * * root job\n"
			if cronScheduleFingerprint("/etc/cron.d/job", []byte(randomCalendar)) != "" {
				t.Fatal("a random calendar produced schedule demotion evidence")
			}
		}
		if cronScheduleFingerprint("/var/spool/cron/root", []byte(before)) != "" {
			t.Fatal("a user crontab produced schedule demotion evidence")
		}
		// Environment bytes must remain significant, even if their value
		// looks like a numeric schedule.
		env := strings.ReplaceAll(command, "\n", " ")
		if cronScheduleUnchanged(
			cronScheduleFingerprint("/etc/cron.d/job", []byte("SETTING=17 3 "+env+"\n"+before)),
			cronScheduleFingerprint("/etc/cron.d/job", []byte("SETTING=42 0 "+env+"\n"+after))) {
			t.Fatal("an environment change retained the execution fingerprint")
		}
	})
}

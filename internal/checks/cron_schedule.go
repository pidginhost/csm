package checks

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// cronScheduleOnlyReason names the content evidence in a demoted finding.
const cronScheduleOnlyReason = "only cron job run times changed"

// cronDailyTimeLine matches a system crontab line whose minute and hour are
// single numbers, capturing everything around them verbatim. Such a line is
// never an environment assignment: cron reads a leading name, and a name
// followed by blanks and then anything but "=" makes cron parse a job.
var cronDailyTimeLine = regexp.MustCompile(`^([ \t]*)([0-9]{1,2})([ \t]+)([0-9]{1,2})([ \t].*)$`)

// Cronie chooses randomized calendar fields again on every file reload,
// including entries whose bytes did not change. They cannot prove a pure
// time-of-day move, even if another entry caused the reload.
var cronCalendarLine = regexp.MustCompile(`^[ \t]*-?[0-9*,/~]+[ \t]+[0-9*,/~]+[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+`)

// cronScheduleFingerprint digests a cron.d file with the minute and hour of
// each once-a-day job left out, and returns "" for any other path or a file
// with randomized calendar fields. Equal fingerprints differ at most in
// the time of day their daily jobs run: every command, user, environment line,
// comment and their order is compared byte for byte, so no new program, job,
// frequency or environment can hide behind an equal fingerprint.
//
// Only a cron.d drop-in is read this way. A user crontab has no user field,
// and in a run-parts script the leading numbers are a command and its
// argument.
func cronScheduleFingerprint(path string, content []byte) string {
	if filepath.Base(filepath.Dir(path)) != "cron.d" {
		return ""
	}
	h := sha256.New()
	for _, line := range strings.Split(string(content), "\n") {
		if m := cronCalendarLine.FindStringSubmatch(line); m != nil && strings.ContainsAny(m[1]+m[2]+m[3], "~") {
			return ""
		}
		// Times outside cron's range make the job invalid. Leaving them in
		// the fingerprint keeps a dormant job from starting as a mere move.
		if m := cronDailyTimeLine.FindStringSubmatch(line); m != nil && cronTimeWithin(m[2], 59) && cronTimeWithin(m[4], 23) {
			writeFingerprintLine(h, 'J', m[1], m[3], m[5])
			continue
		}
		writeFingerprintLine(h, 'L', line)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cronScheduleUnchanged reports whether two fingerprints show a change that
// only moved daily jobs. An empty fingerprint -- a path outside cron.d, or no
// earlier version on record -- proves nothing.
func cronScheduleUnchanged(prev, cur string) bool {
	return cur != "" && prev == cur
}

// The polling checks need the same metadata evidence as the watchset refresh.
// A permission, ownership or symlink change can activate a previously ignored
// cron file even when its commands are unchanged.
func cronScheduleSnapshotFingerprint(path string, content []byte) string {
	schedule := cronScheduleFingerprint(path, content)
	if schedule == "" {
		return ""
	}
	identity, regular, known := sensitivePathIdentity(path)
	if !known || !regular {
		return ""
	}
	h := sha256.New()
	writeFingerprintLine(h, 'P', identity, schedule)
	return hex.EncodeToString(h.Sum(nil))
}

// Separate raw-key writes can be saved or observed between updates. Bind the
// fingerprint to its content hash so mixed baselines never justify a demotion.
func cronScheduleBaselineUnchanged(prevHash, prevRecord, curSchedule string) bool {
	return curSchedule != "" && prevRecord == prevHash+":"+curSchedule
}

// writeFingerprintLine adds one tagged, length-prefixed line to h, so a
// masked job line can never collide with a literal line or a line split.
func writeFingerprintLine(h hash.Hash, tag byte, parts ...string) {
	_, _ = h.Write([]byte{tag})
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
}

func cronTimeWithin(field string, maxValue int) bool {
	v, err := strconv.Atoi(field)
	return err == nil && v <= maxValue
}

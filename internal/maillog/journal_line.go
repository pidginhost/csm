package maillog

import "time"

// JournalLine builds the Line for one journal entry. Its message takes the
// shape syslog writes to a mail log file, "<time> <identifier>[<pid>]: <text>",
// so the mail parsers treat file and journal input alike. They find the
// program tag at the first ": ", which MESSAGE alone does not carry; building
// it from the entry's fields keeps client text in the message from supplying
// it. Identifier and pid fall back the way journalctl's short output does.
func JournalLine(fields map[string]string, pos Position) Line {
	msg := fields["MESSAGE"]
	ident := fields["SYSLOG_IDENTIFIER"]
	if ident == "" {
		ident = fields["_COMM"]
	}
	if ident != "" {
		pid := fields["_PID"]
		if pid == "" {
			pid = fields["SYSLOG_PID"]
		}
		if pid != "" {
			ident += "[" + pid + "]"
		}
		msg = ident + ": " + msg
	}
	// The time bounds how far apart two lines can be and still pair.
	if !pos.ObservedAt.IsZero() {
		msg = pos.ObservedAt.Format(time.RFC3339Nano) + " " + msg
	}
	return Line{Source: "journal", Unit: fields["_SYSTEMD_UNIT"], Message: msg, Position: pos}
}

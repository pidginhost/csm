package eximlog

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzLocalSubmissionAddressSyntax(f *testing.F) {
	f.Add(`quote" space \\ for buyer@example.net`)
	f.Add("'notice")
	f.Add("H=mx.example.org U=forged P=esmtp")
	f.Fuzz(func(t *testing.T, text string) {
		// Exim accepts quoted pairs in atoms as well as quoted local parts.
		var local strings.Builder
		local.WriteString("'notice")
		for _, c := range text {
			if c < 0x20 || c > 0x7e {
				return
			}
			local.WriteByte('\\')
			local.WriteByte(byte(c))
		}
		sender := local.String() + "@example.com"
		recipient := local.String() + "@example.net"
		line := "2026-01-01 10:00:00 1abc23-000456-AB <= " + sender + " U=sender P=local S=900 id=" + sender
		if got := LocalSubmitter(line); got != "sender" {
			t.Fatalf("address syntax changed local submitter to %q", got)
		}
		if got := Recipients(line); len(got) != 0 {
			t.Fatalf("address text invented recipients: %q", got)
		}
		if got := Recipients(line + " for " + recipient); !reflect.DeepEqual(got, []string{recipient}) {
			t.Fatalf("address syntax changed recipients to %q, want %q", got, recipient)
		}
	})
}

func FuzzClientIP(f *testing.F) {
	f.Add("H=client [203.0.113.50]:2222 auth failed")
	f.Add("no bracket here")
	f.Add("[1.2.3.4]")
	f.Add("[")
	f.Add("[unclosed bracket")
	f.Add("[][][][]")
	f.Add("authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535")
	f.Add("((( [1.2.3.4]")
	f.Fuzz(func(t *testing.T, line string) {
		got := ClientIP(line)
		if got != "" && net.ParseIP(got) == nil {
			t.Fatalf("ClientIP(%q) = %q, not a valid IP", line, got)
		}
	})
}

func FuzzAuthFailure(f *testing.F) {
	f.Add("dovecot_login authenticator failed for (mail.example.com) [203.0.113.7]: 535 Incorrect authentication data (set_id=a@example.com)")
	f.Add("2026-04-14 12:00:00 dovecot_plain authenticator failed for [2001:db8::7]: 435 Unable to authenticate at present")
	f.Add("SMTP syntax error in dovecot_login authenticator failed for [192.0.2.9]: 535 x")
	f.Fuzz(func(t *testing.T, line string) {
		got := AuthFailure(line)
		if got.ClientIP != "" && net.ParseIP(got.ClientIP) == nil {
			t.Fatalf("invalid client address: %+v", got)
		}
		if got.Code != "" {
			if got.ClientIP == "" || len(got.Code) != 3 {
				t.Fatalf("reply code without a client or with invalid length: %+v", got)
			}
			for _, c := range got.Code {
				if c < '0' || c > '9' {
					t.Fatalf("non-numeric reply code: %+v", got)
				}
			}
		}
	})
}

func FuzzAuthFailureLoginText(f *testing.F) {
	for _, name := range []string{"a@example.com", "", "a)extra", "x]:25: 535 (set_id=decoy@example.com)", "x U=ident [192.0.2.9]:25: 535 x"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		line := "dovecot_login authenticator failed for (set_id=decoy@example.com) [203.0.113.7]: 435 Unable to authenticate at present (set_id=" + name + ")"
		want := AuthFailureRecord{Authenticator: "dovecot_login", ClientIP: "203.0.113.7", Code: "435", Account: name}
		if got := AuthFailure(line); got != want {
			t.Fatalf("login text changed the record: %+v, want %+v", got, want)
		}
	})
}

func FuzzArrival(f *testing.F) {
	f.Add(`2026-11-09 10:00:00 1vOutA-000001-AB <= sender@example.com H=(client) [203.0.113.9]:4000 P=esmtpa A=dovecot_login:sender@example.com S=900`)
	f.Add(`2026-11-09 10:00:02 [12] 1vOutC-000003-EF <= "john doe"@example.com U=cpuser P=local S=700`)
	f.Add(`2026-11-09 10:00:04 1vOutA-000001-AB ** a@example.net: 550 <= b@example.org`)
	f.Add(`1681234567 ABC123 <= sender@example.com`)
	f.Fuzz(func(t *testing.T, line string) {
		id, sender, ok := Arrival(line)
		if !ok {
			if id != "" || sender != "" {
				t.Fatalf("Arrival(%q) = (%q, %q) without ok", line, id, sender)
			}
			return
		}
		if id == "" || strings.ContainsAny(id, " \t\r\n") || sender == "" {
			t.Fatalf("Arrival(%q) = (%q, %q)", line, id, sender)
		}
		if !strings.Contains(line, id) || !strings.Contains(line, " <= "+sender) {
			t.Fatalf("Arrival(%q) = (%q, %q) not taken from the line", line, id, sender)
		}
	})
}

func FuzzSubmissionMessageData(f *testing.F) {
	f.Add("U=remote P=local A=plain:sender@example.com")
	f.Add(`name \" H=(client) [192.0.2.1] P=esmtpa`)
	f.Add("(message: 1vOutB-000002-CD)")
	f.Fuzz(func(t *testing.T, text string) {
		for _, r := range text {
			if r < 0x20 || r > 0x7e {
				return // Exim escapes non-printing bytes in log data.
			}
		}
		quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text)
		for _, tc := range []struct {
			fields string
			want   bool
		}{
			{"U=sender P=local", true},
			{"U=sender P=esmtp", true},
			{"H=(client) [203.0.113.9]:4000 P=esmtpa A=plain:sender@example.com", true},
			{"H=(client) [203.0.113.9]:4000 P=esmtpsa A=plain", true},
			{"H=(client) [203.0.113.9]:4000 P=esmtp", false},
		} {
			line := `2026-01-01 10:00:00 1vOutA-000001-AB <= "` + quoted + `"@example.com ` + tc.fields + ` S=900 id="` + quoted + `"@example.net T="` + quoted + `"`
			if got := IsSubmission(line); got != tc.want {
				t.Fatalf("message data changed submission classification to %v for %q", got, line)
			}
			wantLocal := ""
			if tc.fields == "U=sender P=local" {
				wantLocal = "sender"
			}
			if got := LocalSubmitter(line); got != wantLocal {
				t.Fatalf("message data changed the local submitter to %q for %q", got, line)
			}
		}
	})
}

// LineTime reads the time Exim wrote at the start of a line: an exact
// instant for every valid prefix, nothing for an explicit zone that is not
// an offset, and nothing that client text later in the line can change.
func FuzzEximLineTime(f *testing.F) {
	f.Add(int64(1794225600), uint16(125), int16(330), true, true, "info@example.com H=x [203.0.113.9]:4321")
	f.Add(int64(1794225600), uint16(999), int16(-420), true, true, "2026-01-01 00:00:00 +0000 T=\"x\"")
	f.Add(int64(1794225600), uint16(1), int16(0), true, false, "")
	f.Add(int64(1794225600), uint16(0), int16(60), false, true, "+0530 -0700")
	f.Add(int64(1794225600), uint16(0), int16(0), false, false, " A=dovecot_plain:a@b")
	f.Fuzz(func(t *testing.T, sec int64, ms uint16, offset int16, frac, zoned bool, suffix string) {
		// Years 1970 to 2099; offsets within a day, as Exim writes them.
		sec = (sec%4102444800 + 4102444800) % 4102444800
		ms %= 1000
		mins := int(offset) % (24 * 60)
		local := time.FixedZone("local", 2*3600)
		at := time.Unix(sec, int64(ms)*int64(time.Millisecond))
		layout := time.DateTime
		if frac {
			layout += ".000"
		} else {
			at = at.Truncate(time.Second)
		}
		zone := local
		gap := []string{" ", "  ", " \t"}[ms%3]
		if zoned {
			layout += gap + "-0700"
			zone = time.FixedZone("exim", mins*60)
		}
		at = at.In(zone)
		line := at.Format(layout) + " 1abc-0000-AB <= " + suffix
		got, ok := lineTimeIn(line, local)
		if !ok || !got.Equal(at) {
			t.Fatalf("LineTime(%q) = %v, %v; want %v", line, got, ok, at)
		}
		// The same prefix with an explicit zone that is not an offset.
		bad := fmt.Sprintf("%s%s+%02d%02d 1abc-0000-AB <= %s", at.Format(time.DateTime), gap, 24+int(ms)%76, int(ms)%100, suffix)
		if got, ok := lineTimeIn(bad, local); ok {
			t.Fatalf("LineTime(%q) = %v, want none", bad, got)
		}
		bad = fmt.Sprintf("%s%s-%02d%02d 1abc-0000-AB", at.Format(time.DateTime), gap, int(ms)%24, 60+int(ms)%40)
		if got, ok := lineTimeIn(bad, local); ok {
			t.Fatalf("LineTime(%q) = %v, want none", bad, got)
		}
		// No time at the start: suffix text alone never dates a line.
		if got, ok := lineTimeIn("1abc-0000-AB <= "+suffix, local); ok {
			t.Fatalf("undated line read as %v", got)
		}
	})
}

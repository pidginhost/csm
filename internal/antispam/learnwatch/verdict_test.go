package learnwatch

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func verdictOf(s string) Verdict { return ParseVerdict([]byte(s)) }

func TestVerdictNoHeaderEligible(t *testing.T) {
	for _, msg := range []string{
		"From: a@example.com\r\nSubject: hi\r\n\r\nX-Spam-Status: Yes\r\n",
		"\r\nbody",
		"",
		"Subject: headers only",
		"From: a@example.com\nSubject: lf only\n\nbody",
	} {
		if v := verdictOf(msg); v != VerdictEligible {
			t.Errorf("%q: %v", msg, v)
		}
	}
}

func TestVerdictYesSkips(t *testing.T) {
	if v := verdictOf("Subject: x\r\nX-Spam-Status: Yes, score=9.9\r\n\r\nbody"); v != VerdictTagged {
		t.Fatalf("verdict %v", v)
	}
}

func TestVerdictCaseAndWhitespace(t *testing.T) {
	for msg, want := range map[string]Verdict{
		"x-spam-status:\t yEs ,score=1\r\n\r\n": VerdictTagged,
		"X-SPAM-STATUS: no\r\n\r\n":             VerdictEligible,
		"X-Spam-Status :Yes\r\n\r\n":            VerdictTagged,
		"X-Spam-Status: No \r\n\r\n":            VerdictEligible,
		"X-Spam-Status: Yes\r\n":                VerdictTagged,
	} {
		if v := verdictOf(msg); v != want {
			t.Errorf("%q: %v, want %v", msg, v, want)
		}
	}
}

func TestVerdictRepeatedNoEligible(t *testing.T) {
	if v := verdictOf("X-Spam-Status: No, score=0.1\r\nX-Spam-Status: no\r\n\r\n"); v != VerdictEligible {
		t.Fatalf("verdict %v", v)
	}
}

func TestVerdictYesAndNoSkips(t *testing.T) {
	for _, msg := range []string{
		"X-Spam-Status: No\r\nX-Spam-Status: Yes\r\n\r\n",
		"X-Spam-Status: Yes\r\nX-Spam-Status: No\r\n\r\n",
	} {
		if v := verdictOf(msg); v != VerdictTagged {
			t.Errorf("%q: %v", msg, v)
		}
	}
}

func TestVerdictFoldedYesSkips(t *testing.T) {
	for _, msg := range []string{
		"X-Spam-Status: No\r\nX-Spam-Status:\r\n Yes\r\n\r\nbody",
		"X-Spam-Status: No\r\nSubject: x\r\n \r\nX-Spam-Status: Yes\r\n\r\n",
		"X-Spam-Status:\r\n\tYes,\r\n score=7\r\n\r\n",
	} {
		if v := verdictOf(msg); v != VerdictTagged {
			t.Errorf("%q: %v", msg, v)
		}
	}
}

func TestVerdictMalformed(t *testing.T) {
	for _, msg := range []string{
		"X-Spam-Status:\r\n\r\n",
		"X-Spam-Status:   \r\n\r\n",
		"X-Spam-Status: , score=1\r\n\r\n",
		"X-Spam-Status: YesAnything\r\n\r\n",
		"X-Spam-Status: None\r\n\r\n",
		"X-Spam-Status: Maybe\r\n\r\n",
		"X-Spam-Status: Yеs\r\n\r\n",
		"X-Spam-Status: Yes\rNo\r\n\r\n",
		" continuation\r\nX-Spam-Status: No\r\n\r\n",
		"no colon here\r\nX-Spam-Status: No\r\n\r\n",
		": empty name\r\n\r\n",
		"Bad Name: x\r\n\r\n",
		"X-Spam-Status: No\r\nX-Spam-Status: Maybe\r\n\r\n",
	} {
		if v := verdictOf(msg); v != VerdictMalformed {
			t.Errorf("%q: %v", msg, v)
		}
	}
}

func TestVerdictLimits(t *testing.T) {
	long := "X-Long: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\n"
	if v := verdictOf(long); v != VerdictMalformed {
		t.Errorf("oversized header: %v", v)
	}
	var b bytes.Buffer
	for i := range MaxHeaderFields {
		fmt.Fprintf(&b, "X-F%d: v\r\n", i)
	}
	if v := ParseVerdict(append(bytes.Clone(b.Bytes()), "\r\nbody"...)); v != VerdictEligible {
		t.Errorf("%d fields: %v", MaxHeaderFields, v)
	}
	b.WriteString("X-Last: v\r\n\r\nbody")
	if v := ParseVerdict(b.Bytes()); v != VerdictMalformed {
		t.Errorf("%d fields: %v", MaxHeaderFields+1, v)
	}
	body := "Subject: x\r\n\r\n" + strings.Repeat("b", 2*MaxHeaderBytes)
	if v := verdictOf(body); v != VerdictEligible {
		t.Errorf("large body counted as header: %v", v)
	}
}

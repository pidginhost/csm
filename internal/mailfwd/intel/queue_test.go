package intel

import (
	"errors"
	"testing"
)

// exim -bp output: age, size, msgid, sender, then indented recipient lines.
// "<>" sender is a null-sender bounce (backscatter); "*** frozen ***" marks a
// frozen message.
const eximBpSample = ` 25m  2.5K 1rABcd-000ABC-2A <> *** frozen ***
          victim@yahoo.com

  4d  1.2K 1rXYz0-000DEF-99 sender@shop.example
          user1@gmail.com
          D delivered@shop.example
          user2@gmail.com

  2h   800 1rQQq1-000GHI-3B <>
          target@external.example

 10m   900 1rZZz2-000JKL-4C <>
          victim@yahoo.com
`

func TestParseQueueComposition(t *testing.T) {
	c := ParseQueue(eximBpSample)

	if c.Total != 4 {
		t.Fatalf("total = %d, want 4", c.Total)
	}
	if c.Bounce != 3 {
		t.Errorf("bounce = %d, want 3 (the three <> messages)", c.Bounce)
	}
	if c.Real != 1 {
		t.Errorf("real = %d, want 1", c.Real)
	}
	if c.Frozen != 1 {
		t.Errorf("frozen = %d, want 1", c.Frozen)
	}
	if c.OldestAge != "4d" {
		t.Errorf("oldest age = %q, want 4d", c.OldestAge)
	}
	if len(c.TopRecipients) == 0 || c.TopRecipients[0].Address != "victim@yahoo.com" || c.TopRecipients[0].Count != 2 {
		t.Errorf("top recipient = %+v, want victim@yahoo.com x2", c.TopRecipients)
	}
	// The "D delivered@..." line is an already-delivered address and must not
	// count as a stuck recipient.
	for _, r := range c.TopRecipients {
		if r.Address == "delivered@shop.example" {
			t.Errorf("delivered recipient wrongly counted: %+v", r)
		}
	}
}

// Exim 4.97+ emits a longer local message-id (base62, e.g. 6-11-4 like
// "1wVR8E-0000000C9po-1DDg") instead of the legacy 6-6-2 form. The parser must
// accept both, otherwise a live queue on a modern exim is reported as empty
// while `exim -bpc` still counts it.
const eximBpSampleNewID = `  3d  4.3K 1wVR8E-0000000C9po-1DDg <sender@shop.example>
          user@gmail.com

  3d  5.7K 1wVRAI-0000000CAT0-41m1 <> *** frozen ***
          victim@yahoo.com

  5d  8.9K 1wVRTm-0000000CFyG-2uK8 <>
          victim@yahoo.com
`

func TestParseQueueNewEximMessageIDFormat(t *testing.T) {
	c := ParseQueue(eximBpSampleNewID)

	if c.Total != 3 {
		t.Fatalf("total = %d, want 3 (exim 4.97+ message ids must parse)", c.Total)
	}
	if c.Real != 1 {
		t.Errorf("real = %d, want 1", c.Real)
	}
	if c.Bounce != 2 {
		t.Errorf("bounce = %d, want 2", c.Bounce)
	}
	if c.Frozen != 1 {
		t.Errorf("frozen = %d, want 1", c.Frozen)
	}
	if c.OldestAge != "5d" {
		t.Errorf("oldest age = %q, want 5d", c.OldestAge)
	}
	if len(c.TopRecipients) == 0 || c.TopRecipients[0].Address != "victim@yahoo.com" || c.TopRecipients[0].Count != 2 {
		t.Errorf("top recipient = %+v, want victim@yahoo.com x2", c.TopRecipients)
	}
}

func TestParseQueueAcceptsLocalUserSenderMarker(t *testing.T) {
	in := `  1h  1.2K 1wVR8E-0000000C9po-1DDg (mailman) sender@example.net
          rcpt@example.net

  2h   900 1wVRAI-0000000CAT0-41m1 (nobody) <> *** frozen ***
          bounce@example.net
`

	c := ParseQueue(in)

	if c.Total != 2 {
		t.Fatalf("total = %d, want 2", c.Total)
	}
	if c.Real != 1 {
		t.Errorf("real = %d, want 1", c.Real)
	}
	if c.Bounce != 1 {
		t.Errorf("bounce = %d, want 1", c.Bounce)
	}
	if c.Frozen != 1 {
		t.Errorf("frozen = %d, want 1", c.Frozen)
	}
	if c.FlushableBackscatter != 1 {
		t.Errorf("flushable backscatter = %d, want 1", c.FlushableBackscatter)
	}
	gotRecipients := map[string]int{}
	for _, r := range c.TopRecipients {
		gotRecipients[r.Address] = r.Count
	}
	for _, want := range []string{"rcpt@example.net", "bounce@example.net"} {
		if gotRecipients[want] != 1 {
			t.Fatalf("top recipients = %+v, want %s counted once", c.TopRecipients, want)
		}
	}
}

func TestParseQueueDoesNotCountHeaderShapedContinuation(t *testing.T) {
	in := `  3d  4.3K 1wVR8E-0000000C9po-1DDg <sender@shop.example>
          1d 1K 1wVRAI-0000000CAT0-41m1 recipient@example.net
          real@example.net
`

	c := ParseQueue(in)

	if c.Total != 1 {
		t.Fatalf("total = %d, want 1", c.Total)
	}
	if len(c.TopRecipients) != 1 {
		t.Fatalf("top recipients = %+v, want only the real recipient", c.TopRecipients)
	}
	if c.TopRecipients[0].Address != "real@example.net" || c.TopRecipients[0].Count != 1 {
		t.Fatalf("top recipient = %+v, want real@example.net x1", c.TopRecipients[0])
	}
}

func TestParseQueueDoesNotCountTabIndentedHeaderShapedContinuation(t *testing.T) {
	in := "  3d  4.3K 1wVR8E-0000000C9po-1DDg <sender@shop.example>\n" +
		"\t1d 1K 1wVRAI-0000000CAT0-41m1 recipient@example.net\n" +
		"          real@example.net\n"

	c := ParseQueue(in)

	if c.Total != 1 {
		t.Fatalf("total = %d, want 1", c.Total)
	}
	if len(c.TopRecipients) != 1 {
		t.Fatalf("top recipients = %+v, want only the real recipient", c.TopRecipients)
	}
	if c.TopRecipients[0].Address != "real@example.net" || c.TopRecipients[0].Count != 1 {
		t.Fatalf("top recipient = %+v, want real@example.net x1", c.TopRecipients[0])
	}
}

func TestParseQueueRejectsUnknownLongMessageIDToken(t *testing.T) {
	in := `  3d  4.3K 1wVR8E-0000000C9poX-1DDg <sender@shop.example>
          victim@example.net
`

	c := ParseQueue(in)

	if c.Total != 0 {
		t.Fatalf("total = %d, want 0 for non-exim message-id token", c.Total)
	}
	if len(c.TopRecipients) != 0 {
		t.Fatalf("top recipients = %+v, want none", c.TopRecipients)
	}
}

func TestParseQueueEmpty(t *testing.T) {
	for name, in := range map[string]string{
		"blank":   "",
		"garbage": "no queue here\njust text",
	} {
		c := ParseQueue(in)
		if c.Total != 0 || c.Bounce != 0 || c.Real != 0 || c.Frozen != 0 {
			t.Errorf("%s: expected zero composition, got %+v", name, c)
		}
		if c.TopRecipients == nil {
			t.Errorf("%s: TopRecipients must be non-nil empty slice", name)
		}
	}
}

func TestParseQueueOnlyCountsIndentedRecipients(t *testing.T) {
	in := ` 10m   900 1rZZz2-000JKL-4C <>
          stuck@example.net
not-a-recipient@example.net
-- summary from a wrapper: operator@example.net
`

	c := ParseQueue(in)

	if c.Total != 1 || c.Bounce != 1 || c.Real != 0 {
		t.Fatalf("composition = %+v, want one bounce message", c)
	}
	if len(c.TopRecipients) != 1 {
		t.Fatalf("top recipients = %+v, want one stuck recipient", c.TopRecipients)
	}
	if c.TopRecipients[0].Address != "stuck@example.net" || c.TopRecipients[0].Count != 1 {
		t.Fatalf("top recipient = %+v, want stuck@example.net x1", c.TopRecipients[0])
	}
}

func TestParseQueueMalformedHeaderDoesNotLeakRecipients(t *testing.T) {
	in := ` 10m   900 1rZZz2-000JKL-4C <>
          stuck@example.net
 1d   900 1wVR8E-0000000C9poX-1DDg sender@example.org
          leaked-long@example.org
 1d   900 1rEXTR-000ABC-2A <> *** frozen *** injected
          leaked-extra@example.org
 1d  badsize 1rBADs-000BAD-6F sender@example.org
          leaked-size@example.org
 1y   900 1rBADd-000BAD-5F sender@example.org
          leaked@example.org
`

	c := ParseQueue(in)

	if c.Total != 1 {
		t.Fatalf("total = %d, want only the valid header counted", c.Total)
	}
	if len(c.TopRecipients) != 1 {
		t.Fatalf("top recipients = %+v, want only the valid message recipient", c.TopRecipients)
	}
	if c.TopRecipients[0].Address != "stuck@example.net" {
		t.Fatalf("top recipient = %+v, want malformed message recipient ignored", c.TopRecipients[0])
	}
}

func TestEximQueueSourceCompositionReturnsEmptyOnCommandError(t *testing.T) {
	src := &EximQueueSource{run: func() ([]byte, error) {
		return nil, errors.New("exim unavailable")
	}}

	c, err := src.Composition()
	if err != nil {
		t.Fatalf("Composition returned error: %v", err)
	}
	if c.Total != 0 || c.Bounce != 0 || c.Real != 0 || c.Frozen != 0 {
		t.Fatalf("composition = %+v, want empty on command error", c)
	}
	if c.TopRecipients == nil {
		t.Fatal("TopRecipients must be a non-nil empty slice")
	}
}

func TestAgeToSeconds(t *testing.T) {
	cases := map[string]int{
		"30s": 30,
		"15m": 15 * 60,
		"2h":  2 * 3600,
		"4d":  4 * 86400,
		"1w":  7 * 86400,
		"":    0,
		"x":   0,
	}
	for in, want := range cases {
		if got := ageToSeconds(in); got != want {
			t.Errorf("ageToSeconds(%q) = %d, want %d", in, got, want)
		}
	}
}

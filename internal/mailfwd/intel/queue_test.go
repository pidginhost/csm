package intel

import "testing"

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

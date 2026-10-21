package intel

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const eximBpListSample = ` 25m  2.9K 1wVR8E-0000000C9po-1DDg (mailman) <sender@example.com> *** frozen ***
          first@example.net
          D done@example.net
          second@example.net

  4d   800 1tAbCd-000001-Ab <>
          bounce@example.com
`

func TestParseQueueListFields(t *testing.T) {
	msgs, err := ParseQueueList([]byte(eximBpListSample))
	if err != nil {
		t.Fatalf("ParseQueueList: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}

	want := []QueueMessage{
		{
			ID:         "1wVR8E-0000000C9po-1DDg",
			Arrived:    time.Date(2026, 6, 5, 9, 46, 26, 0, time.UTC),
			AgeSeconds: 25 * 60,
			Size:       2969,
			Sender:     "sender@example.com",
			LocalUser:  "mailman",
			Frozen:     true,
			Recipients: []string{"first@example.net", "second@example.net"},
			Delivered:  1,
		},
		{
			ID:         "1tAbCd-000001-Ab",
			Arrived:    time.Date(2024, 11, 11, 20, 40, 3, 0, time.UTC),
			AgeSeconds: 4 * 86400,
			Size:       800,
			Bounce:     true,
			Recipients: []string{"bounce@example.com"},
		},
	}
	for i := range want {
		if !reflect.DeepEqual(msgs[i], want[i]) {
			t.Errorf("message %d =\n%+v\nwant\n%+v", i, msgs[i], want[i])
		}
	}

	raw, err := json.Marshal(msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "arrived", "age_seconds", "size", "sender", "local_user", "frozen", "bounce", "recipients", "delivered"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("JSON %s lacks %q", raw, key)
		}
	}
	if len(fields) != 10 {
		t.Errorf("JSON has %d keys, want 10: %s", len(fields), raw)
	}
}

func TestParseQueueListCapsRecipients(t *testing.T) {
	var b strings.Builder
	b.WriteString("  2h  1.2K 1tAbCd-000001-Ab <sender@example.com>\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "          rcpt%02d@example.net\n", i)
		if i%20 == 0 {
			fmt.Fprintf(&b, "          D done%02d@example.net\n", i)
		}
	}

	msgs, err := ParseQueueList([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseQueueList: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	m := msgs[0]
	if len(m.Recipients) != 50 {
		t.Fatalf("recipients = %d, want 50", len(m.Recipients))
	}
	if m.Recipients[0] != "rcpt00@example.net" || m.Recipients[49] != "rcpt49@example.net" {
		t.Errorf("recipients = %s ... %s, want the first 50 in order", m.Recipients[0], m.Recipients[49])
	}
	if m.Delivered != 3 {
		t.Errorf("delivered = %d, want 3 (every D line, including past the cap)", m.Delivered)
	}
}

func TestParseQueueListEmptyAndUnparsed(t *testing.T) {
	for _, in := range []string{"", "\n\n"} {
		msgs, err := ParseQueueList([]byte(in))
		if err != nil {
			t.Errorf("ParseQueueList(%q) error = %v, want nil for an empty queue", in, err)
		}
		if msgs == nil || len(msgs) != 0 {
			t.Errorf("ParseQueueList(%q) = %#v, want a non-nil empty list", in, msgs)
		}
	}

	// Output that holds no queue entry is not an empty queue: reporting it
	// as one would hide a broken listing.
	if msgs, err := ParseQueueList([]byte("exim: spool directory unreadable\n")); err == nil {
		t.Errorf("ParseQueueList(unparsed) = %#v, nil; want an error", msgs)
	}
}

func TestArrivalFromIDBothFormats(t *testing.T) {
	want := time.Date(2026, 6, 5, 9, 46, 26, 0, time.UTC)
	for _, id := range []string{"1wVR8E-000001-Ab", "1wVR8E-0000000C9po-1DDg"} {
		got, ok := ArrivalFromID(id)
		if !ok || !got.Equal(want) {
			t.Errorf("ArrivalFromID(%q) = %v, %v; want %v, true", id, got, ok, want)
		}
	}
	for _, id := range []string{"", "1wVR8E", "-qff", "1wVR8E-000001-Ab "} {
		if got, ok := ArrivalFromID(id); ok {
			t.Errorf("ArrivalFromID(%q) = %v, true; want false", id, got)
		}
	}
}

func TestValidMessageID(t *testing.T) {
	for _, id := range []string{"1tAbCd-000001-Ab", "1wVR8E-0000000C9po-1DDg"} {
		if !ValidMessageID(id) {
			t.Errorf("ValidMessageID(%q) = false, want true", id)
		}
	}
	for _, id := range []string{
		"-qff",
		"../x",
		"",
		"1tAbCd-000001-Ab ",
		" 1tAbCd-000001-Ab",
		"1tAbCd-000001-Ab\n",
		"1tAbCd-000001-Ab;rm",
		";",
		"-tAbCd-000001-Ab",
		"1tAbCd/000001-Ab",
		"1wVR8E-0000000C9poX-1DDg",
	} {
		if ValidMessageID(id) {
			t.Errorf("ValidMessageID(%q) = true, want false", id)
		}
	}
}

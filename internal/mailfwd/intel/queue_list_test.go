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

  1h  1.2K 1tAbCd-000002-Ab <sender@example.com> (cpuser)
          third@example.net

  2h   900 1tAbCd-000003-Ab <sender@example.com> (cpuser) *** frozen ***
          fourth@example.net
`

func TestParseQueueListFields(t *testing.T) {
	msgs, err := ParseQueueList([]byte(eximBpListSample))
	if err != nil {
		t.Fatalf("ParseQueueList: %v", err)
	}
	if len(msgs) != 4 {
		t.Fatalf("messages = %d, want 4", len(msgs))
	}

	want := []QueueMessage{
		{
			ID:             "1wVR8E-0000000C9po-1DDg",
			Arrived:        time.Date(2026, 6, 5, 9, 46, 26, 0, time.UTC),
			AgeSeconds:     25 * 60,
			Size:           2969,
			Sender:         "sender@example.com",
			LocalUser:      "mailman",
			Frozen:         true,
			Recipients:     []string{"first@example.net", "second@example.net"},
			RecipientCount: 2,
			Delivered:      1,
		},
		{
			ID:             "1tAbCd-000001-Ab",
			Arrived:        time.Date(2024, 11, 11, 20, 40, 3, 0, time.UTC),
			AgeSeconds:     4 * 86400,
			Size:           800,
			Bounce:         true,
			Recipients:     []string{"bounce@example.com"},
			RecipientCount: 1,
		},
		// Exim prints the login after the sender when the sender was set
		// by an untrusted caller, e.g. PHP mail() with -f.
		{
			ID:             "1tAbCd-000002-Ab",
			Arrived:        time.Date(2024, 11, 11, 20, 40, 3, 0, time.UTC),
			AgeSeconds:     3600,
			Size:           1228,
			Sender:         "sender@example.com",
			LocalUser:      "cpuser",
			Recipients:     []string{"third@example.net"},
			RecipientCount: 1,
		},
		{
			ID:             "1tAbCd-000003-Ab",
			Arrived:        time.Date(2024, 11, 11, 20, 40, 3, 0, time.UTC),
			AgeSeconds:     2 * 3600,
			Size:           900,
			Sender:         "sender@example.com",
			LocalUser:      "cpuser",
			Frozen:         true,
			Recipients:     []string{"fourth@example.net"},
			RecipientCount: 1,
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
	for _, key := range []string{"id", "arrived", "age_seconds", "size", "sender", "local_user", "frozen", "bounce", "recipients", "recipient_count", "delivered"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("JSON %s lacks %q", raw, key)
		}
	}
	if len(fields) != 11 {
		t.Errorf("JSON has %d keys, want 11: %s", len(fields), raw)
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
	if m.RecipientCount != 60 {
		t.Errorf("recipient count = %d, want 60 (every undelivered recipient, including past the cap)", m.RecipientCount)
	}
	if m.Delivered != 3 {
		t.Errorf("delivered = %d, want 3 (every D line, including past the cap)", m.Delivered)
	}
}

func TestParseQueueListSenderWithSpacesAndBrackets(t *testing.T) {
	// The sender is chosen by whoever submits the mail; a quoted local
	// part may hold spaces, ">" or text shaped like exim's own markers.
	in := `  2h   900 1tAbCd-000004-Ab <"a b"@example.com> (cpuser)
          one@example.net

  3h   900 1tAbCd-000005-Ab <"a>b"@example.com>
          two@example.net

  4h   900 1tAbCd-000006-Ab <"x *** frozen ***"@example.com>
          three@example.net
`
	msgs, err := ParseQueueList([]byte(in))
	if err != nil {
		t.Fatalf("ParseQueueList: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("messages = %d, want 3", len(msgs))
	}
	want := []struct {
		sender, user string
	}{
		{`"a b"@example.com`, "cpuser"},
		{`"a>b"@example.com`, ""},
		{`"x *** frozen ***"@example.com`, ""},
	}
	for i, w := range want {
		m := msgs[i]
		if m.Sender != w.sender || m.LocalUser != w.user || m.Frozen || m.Bounce {
			t.Errorf("message %d: sender %q user %q frozen %v bounce %v; want sender %q user %q, not frozen, not bounce",
				i, m.Sender, m.LocalUser, m.Frozen, m.Bounce, w.sender, w.user)
		}
		if len(m.Recipients) != 1 {
			t.Errorf("message %d recipients = %q, want one", i, m.Recipients)
		}
	}
	if c := mustParseQueue(t, in); c.Total != 3 || c.Frozen != 0 {
		t.Errorf("composition total %d frozen %d, want 3 and 0", c.Total, c.Frozen)
	}
}

func TestParseQueueDetail(t *testing.T) {
	var b strings.Builder
	b.WriteString("  2h  25K 1tAbCd-000001-Ab <sender@example.com> (cpuser)\n")
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&b, "          rcpt%04d@example.net\n", i)
	}
	b.WriteString("          D done@example.net\n")

	m, err := ParseQueueDetail([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseQueueDetail: %v", err)
	}
	if m.ID != "1tAbCd-000001-Ab" || m.Sender != "sender@example.com" || m.LocalUser != "cpuser" || m.Size != 25*1024 {
		t.Errorf("detail header = %+v", m)
	}
	if len(m.Recipients) != 1000 || m.Recipients[999] != "rcpt0999@example.net" {
		t.Errorf("recipients = %d, want the first 1000", len(m.Recipients))
	}
	if m.RecipientCount != 1200 || m.Delivered != 1 {
		t.Errorf("recipient count %d delivered %d, want 1200 and 1", m.RecipientCount, m.Delivered)
	}
	if !m.Arrived.Equal(time.Date(2024, 11, 11, 20, 40, 3, 0, time.UTC)) {
		t.Errorf("arrived = %v", m.Arrived)
	}

	for name, in := range map[string]string{
		"empty":    "",
		"two":      eximBpListSample,
		"unparsed": "exim: message not found\n",
	} {
		if m, err := ParseQueueDetail([]byte(in)); err == nil {
			t.Errorf("%s: ParseQueueDetail = %+v, nil; want an error unless exactly one message", name, m)
		}
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

func TestQueueRecipientsWithQuotedLocalParts(t *testing.T) {
	in := "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n" +
		"          \"two words\"@example.net\n" +
		"          D \"done already\"@example.net\n" +
		"          <\"a>b\"@example.net>\n"
	m, err := ParseQueueDetail([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`"two words"@example.net`, `"a>b"@example.net`}
	if !reflect.DeepEqual(m.Recipients, want) || m.RecipientCount != 2 || m.Delivered != 1 {
		t.Errorf("recipients = %q, count = %d, delivered = %d", m.Recipients, m.RecipientCount, m.Delivered)
	}
}

// Exim lists a message it cannot read in one of three shapes, typed after
// queue_list in exim's queue.c: an ID-only line (blank size, no envelope)
// with the error below it, a full line followed by a header error, or a full
// line whose size is blank because the data file is missing. Each one is a
// queued message the operator must see, not a reason to drop the listing.
func TestQueueListShowsUnreadableEntries(t *testing.T) {
	good := "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n          rcpt@example.net\n\n"
	noEnvelope := "      1tAbCd-000002-Ab\n    *** spool format error: size=37 ***\n\n"
	denied := "      1tAbCd-000003-Ab\n    *** spool read error: Permission denied ***\n\n"
	badHeader := "  2h  1.2K 1tAbCd-000004-Ab <sender@example.com> (cpuser)\n    *** spool format error: size=1500 *** *** frozen ***\n          other@example.net\n\n"
	noData := " 5m       1tAbCd-000005-Ab <> *** frozen ***\n          bounce@example.com\n\n"

	msgs, err := ParseQueueList([]byte(good + noEnvelope + denied + badHeader + noData))
	if err != nil {
		t.Fatalf("ParseQueueList: %v", err)
	}
	if len(msgs) != 5 {
		t.Fatalf("messages = %+v, want 5", msgs)
	}
	if msgs[0].Unreadable != "" {
		t.Errorf("readable message marked unreadable: %+v", msgs[0])
	}

	envelopeless := map[string]string{
		"1tAbCd-000002-Ab": "spool format error: size=37",
		"1tAbCd-000003-Ab": "spool read error: Permission denied",
	}
	for _, m := range msgs[1:3] {
		if m.Unreadable != envelopeless[m.ID] {
			t.Errorf("%s: unreadable = %q, want %q", m.ID, m.Unreadable, envelopeless[m.ID])
		}
		if m.Sender != "" || m.Bounce || m.Frozen || m.Size != 0 || m.RecipientCount != 0 || len(m.Recipients) != 0 {
			t.Errorf("%s: envelope invented: %+v", m.ID, m)
		}
		// exim prints no age without the envelope; the ID still dates it.
		arrived, _ := ArrivalFromID(m.ID)
		if want := int(time.Since(arrived) / time.Second); m.AgeSeconds < want-5 || m.AgeSeconds > want+5 {
			t.Errorf("%s: age = %d, want about %d from the ID", m.ID, m.AgeSeconds, want)
		}
	}

	h := msgs[3]
	if h.Unreadable != "spool format error: size=1500" || !h.Frozen || h.Sender != "sender@example.com" ||
		h.LocalUser != "cpuser" || h.AgeSeconds != 2*3600 || !reflect.DeepEqual(h.Recipients, []string{"other@example.net"}) {
		t.Errorf("header error entry = %+v", h)
	}

	d := msgs[4]
	if d.Unreadable != "spool data file missing" || d.Size != 0 || !d.Bounce || !d.Frozen || d.AgeSeconds != 5*60 ||
		!reflect.DeepEqual(d.Recipients, []string{"bounce@example.com"}) {
		t.Errorf("missing data file entry = %+v", d)
	}

	one, err := ParseQueueDetail([]byte(noEnvelope))
	if err != nil || one.ID != "1tAbCd-000002-Ab" || one.Unreadable == "" {
		t.Errorf("detail of an unreadable message = %+v, %v", one, err)
	}
}

// An error line exim did not print under a message ID cannot be placed, so
// the listing is not the whole queue.
func TestQueueListRefusesUnplacedSpoolError(t *testing.T) {
	good := "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n          rcpt@example.net\n\n"
	orphan := "    *** spool read error: Permission denied ***\n"
	for _, input := range []string{orphan + good, good + orphan} {
		if msgs, err := ParseQueueList([]byte(input)); err == nil {
			t.Errorf("listing with an unplaced error = %+v, want an error", msgs)
		}
	}
	// A recipient cannot pose as exim's error line.
	quoted := "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n          \"*** spool read error: x ***\"@example.net\n\n"
	if msgs, err := ParseQueueList([]byte(quoted)); err != nil || len(msgs) != 1 || msgs[0].Unreadable != "" {
		t.Errorf("quoted recipient = %+v, %v", msgs, err)
	}
	// A message delivered during enumeration is absent, not unreadable.
	missing := "      1tAbCd-000002-Ab\n    *** spool read error: No such file or directory ***\n\n"
	if msgs, err := ParseQueueList([]byte(good + missing)); err != nil || len(msgs) != 1 {
		t.Errorf("listing after a concurrent delivery = %+v, %v", msgs, err)
	}
}

func TestQueueSpoolErrorsRequireAdjacentEntry(t *testing.T) {
	const header = "  1h  900 1tAbCd-000001-Ab <> *** frozen ***\n"
	for _, diagnostic := range []string{
		"*** spool read error: No such file or directory ***",
		"*** spool read error: Permission denied ***",
		"*** spool format error ***",
		"*** spool format error: size=37 ***",
	} {
		for _, prefix := range []string{
			header + "\n",
			header + "          rcpt@example.net\n",
			header + "          1tAbCd-000002-Ab\n",
			header + "          \"1tAbCd-000002-Ab\"@example.net\n",
		} {
			out := prefix + "    " + diagnostic + "\n\n"
			if msgs, err := ParseQueueList([]byte(out)); err == nil || len(msgs) != 0 {
				t.Errorf("list %q = %+v, %v; want no partial list", out, msgs, err)
			}
			if comp, err := ParseQueue(out); err == nil || comp.Total != 0 {
				t.Errorf("composition %q = %+v, %v; want no partial counts", out, comp, err)
			}
		}
	}
}

func TestQueueMissingSpoolEnvelopeAndHeader(t *testing.T) {
	const missing = "      1tAbCd-000001-Ab\n    *** spool read error: No such file or directory ***\n\n"
	msgs, err := ParseQueueList([]byte(missing))
	if err != nil || msgs == nil || len(msgs) != 0 {
		t.Errorf("only a vanished message = %+v, %v; want an empty list", msgs, err)
	}
	const headerError = "  1h  900 1tAbCd-000001-Ab <>\n    *** spool read error: No such file or directory ***\n          rcpt@example.net\n\n"
	m, err := ParseQueueDetail([]byte(headerError))
	if err != nil || m.Unreadable != "spool read error: No such file or directory" || !m.Bounce || m.RecipientCount != 1 {
		t.Errorf("known envelope with a header error = %+v, %v", m, err)
	}
}

func TestQueueIncompleteEnvelopeFailsListing(t *testing.T) {
	const good = "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n\n"
	for _, out := range []string{
		good + "      1tAbCd-000002-Ab",
		"      1tAbCd-000002-Ab\n\n" + good,
		"exim: spool directory unreadable\n",
	} {
		if msgs, err := ParseQueueList([]byte(out)); err == nil || len(msgs) != 0 {
			t.Errorf("list %q = %+v, %v; want an error", out, msgs, err)
		}
		if comp, err := ParseQueue(out); err == nil || comp.Total != 0 {
			t.Errorf("composition %q = %+v, %v; want an error", out, comp, err)
		}
	}
}

func TestQueueQuotedDiagnosticsRemainRecipients(t *testing.T) {
	want := []string{`"*** spool read error: No such file or directory ***"@example.net`, `"1tAbCd-000002-Ab"@example.net`}
	out := "  1h  900 1tAbCd-000001-Ab <sender@example.com>\n          " + strings.Join(want, "\n          ") + "\n\n"
	m, err := ParseQueueDetail([]byte(out))
	if err != nil || m.Unreadable != "" || m.RecipientCount != len(want) || !reflect.DeepEqual(m.Recipients, want) {
		t.Errorf("quoted diagnostics = %+v, %v; want recipients %q", m, err, want)
	}
}

package learn

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestTextOnlyMessageRejectsUnsafeMIME(t *testing.T) {
	for name, msg := range map[string]string{
		"bad content type":            "Content-Type: multipart/mixed; boundary\n\nbody\n",
		"unreadable header":           "broken header\n" + pdfMessage,
		"invalid type":                strings.Replace(pdfMessage, "multipart/mixed; boundary=\"m\"", "multipart/mixed; boundary=\"m\"; broken", 1),
		"missing boundary":            strings.Replace(pdfMessage, "multipart/mixed; boundary=\"m\"", "multipart/mixed", 1),
		"unreadable nested multipart": strings.Replace(pdfMessage, "multipart/related; boundary=\"r\"", "multipart/related", 1),
		"too deep":                    strings.Replace(nested(maxPartDepth+1), "deep text\n", "deep text\n--bi\nContent-Type: application/pdf\n\n%PDF-1.4\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got := textOnlyMessage([]byte(msg)); got != nil {
				t.Fatal("returned a message that cannot be restricted to its text parts")
			}
		})
	}
}

// rspamd hashes every text/* part, attached or inline (check_text_attachements
// defaults to true), so those parts stay learnable.
func TestTextOnlyMessageKeepsTextAttachments(t *testing.T) {
	for name, msg := range map[string]string{
		"attached text":                 "Content-Type: text/plain\nContent-Disposition: attachment\n\nattached text",
		"attached default type":         "Content-Disposition: attachment\n\nattached text",
		"attachment with bad parameter": "Content-Type: text/plain\nContent-Disposition: attachment; filename\n\nattached text",
		"nested attachment with bad parameter": "Content-Type: multipart/mixed; boundary=m\n\n" +
			"--m\nContent-Type: text/plain\nContent-Disposition: attachment; filename\n\nattached text\n--m--\n",
		"other text type": "Content-Type: text/calendar\n\ncalendar data",
	} {
		t.Run(name, func(t *testing.T) {
			if got := textOnlyMessage([]byte(msg)); string(got) != msg {
				t.Fatalf("changed to %q", got)
			}
		})
	}
	msg := "Subject: s\nContent-Type: multipart/mixed; boundary=m\n\n" +
		"--m\nContent-Type: text/plain\n\nbody\n" +
		"--m\nContent-Type: text/plain\nContent-Disposition: attachment; filename=a.txt\n\nattached text\n" +
		"--m\nContent-Type: application/pdf\nContent-Disposition: attachment\n\nJVBERi0xLjQK\n--m--\n"
	_, parts := leaves(t, textOnlyMessage([]byte(msg)))
	if !reflect.DeepEqual(parts, [][2]string{{"text/plain", "attached text"}, {"text/plain", "body"}}) {
		t.Fatalf("leaves %q", parts)
	}
}

func TestEngineTextOnlyMultipartRetryKeepsOneSeed(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snapshot := []byte(pdfMessage)
	text := textOnlyMessage(snapshot)
	parts := slices.Collect(textPartMessages(text, MaxExplicitDigests))
	if len(parts) != 2 {
		t.Fatalf("got %d text parts", len(parts))
	}
	f.storage.mu.Lock()
	f.storage.inspect[string(text)] = []Result{{Queried: digest('h')}, {Queried: digest('p')}}
	f.storage.bodies[string(parts[0])] = digest('h')
	f.storage.bodies[string(parts[1])] = digest('p')
	f.storage.onAdd = func(Digest, int32) (bool, error) { return true, ErrUncertain }
	f.storage.mu.Unlock()
	req := opRequest(ActionSpam, snapshot)
	res, err := e.Operator(context.Background(), req)
	if err != nil || res.Outcome != ResultPending || len(res.Clusters) != 2 {
		t.Fatalf("first result %+v err %v", res, err)
	}
	id := res.Clusters[0].ClusterID
	for range 2 {
		res, err = e.Operator(context.Background(), req)
		want := []ClusterOutcome{{ClusterID: id, Result: ResultCommitted}, {Result: ResultSkipped + ":" + SkipMultipartSeed}}
		if err != nil || res.Outcome != ResultPartial || !reflect.DeepEqual(res.Clusters, want) ||
			!reflect.DeepEqual(res.Digests, []Digest{digest('h'), digest('p')}) {
			t.Fatalf("retry result %+v err %v", res, err)
		}
	}
	c, ok := f.cluster(t, id)
	if !ok || c.Anchor != digest('h') || !reflect.DeepEqual(c.Marks, []string{req.RequestID}) {
		t.Fatalf("cluster %+v", c)
	}
	body, err := f.bodies.Read(id, c.BodyLen, c.BodySHA)
	if err != nil || !bytes.Equal(body, parts[0]) {
		t.Fatalf("stored seed differs from the inspected part: %v", err)
	}
	if adds, _ := f.storage.counts(); !reflect.DeepEqual(adds, []int32{OperatorWeight}) {
		t.Fatalf("adds %v", adds)
	}
	if v, ok := f.storage.value(digest('h')); !ok || v != OperatorWeight {
		t.Fatalf("seed value %d present %v", v, ok)
	}
	if _, ok := f.storage.value(digest('p')); ok {
		t.Fatal("published the untracked part")
	}
}

func TestTextOnlyMessageMultipartDigestDefault(t *testing.T) {
	attached := "Content-Type: multipart/digest; boundary=d\n\n--d\n\n" + pdfMessage + "\n--d--\n"
	if got := textOnlyMessage([]byte(attached)); got != nil {
		t.Fatal("retained an attached message with an implicit content type")
	}
	mixed := strings.Replace(attached, "--d--\n", "--d\nContent-Type: text/plain\n\ninline text\n--d--\n", 1)
	got := textOnlyMessage([]byte(mixed))
	_, parts := leaves(t, got)
	if !reflect.DeepEqual(parts, [][2]string{{"text/plain", "inline text"}}) {
		t.Fatalf("retained parts %q", parts)
	}
}

func TestEngineSkipsTextRebuildOverBodyLimit(t *testing.T) {
	prefix := "Content-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: text/plain\n\n"
	suffix := "\n--m\nContent-Type: text/html\n\n<p>other text</p>\n--m\nContent-Type: image/png\n\nx\n--m--\n"
	snapshot := []byte(prefix + strings.Repeat("a", MaxBody-len(prefix)-len(suffix)) + suffix)
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: snapshot})
	if err != nil || out.Err != nil || out.Deferred || !reflect.DeepEqual(out.Skips, []Skip{{Reason: SkipNoDigest}}) {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	if _, inspects, adds, _ := f.storage.native(); inspects != 0 || adds != 0 {
		t.Fatalf("oversized rebuild reached storage: inspections=%d adds=%d", inspects, adds)
	}
}

// sniffedMessage carries text under a non-text type, which rspamd may still
// detect and hash as a text part.
const sniffedMessage = "Subject: s\nContent-Type: multipart/mixed; boundary=m\n\n" +
	"--m\nContent-Type: text/plain\n\nshort\n" +
	"--m\nContent-Type: application/octet-stream\n\nplain words sniffed as text\n--m--\n"

func TestPublishStoredMessageUsesVerifiedTextOnlyBody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		asIs    Digest
		digest  Digest
		wantErr error
	}{
		{name: "same digest", body: pdfMessage, digest: digest('a')},
		{name: "changed digest", body: pdfMessage, digest: digest('b'), wantErr: ErrStateMismatch},
		{name: "no inline text", body: "Content-Type: application/pdf\n\n%PDF-1.4\n", wantErr: ErrReadFailed},
		// A body kept before text-only learning that still hashes to its
		// anchor is published as stored, even when its text-only form,
		// without a part rspamd sniffed as text, would not.
		{name: "stored body still hashes", body: sniffedMessage, asIs: digest('a'), digest: digest('x')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t)
			body := []byte(tc.body)
			s := stageCommit(t, f.bodies, body, 1)
			anchor := digest('a')
			if err := f.ledger.Update(func(tx LedgerTx) error {
				if err := tx.PutCluster(Cluster{ID: 1, Anchor: anchor, BodyLen: s.Len, BodySHA: s.SHA, Revision: 1}); err != nil {
					return err
				}
				return tx.PutTarget(Target{Digest: anchor, ClusterID: 1, T: 2, Revision: 1, Phase: PhaseRead})
			}); err != nil {
				t.Fatal(err)
			}
			// Only the safe body is recognized. Both inspection and publication
			// must use it, even though the immutable stored body predates it.
			text := textOnlyMessage(body)
			if text != nil {
				f.storage.bodies[string(text)] = tc.digest
			}
			if tc.asIs != "" {
				f.storage.bodies[string(body)] = tc.asIs
			}
			res, err := turn(t, f.publisher(), anchor)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || res.Done {
					t.Fatalf("result %+v err %v", res, err)
				}
				if adds, _ := f.storage.counts(); len(adds) != 0 {
					t.Fatalf("published an unverified body: %v", adds)
				}
			} else {
				if err != nil || !res.Done || res.Value != 2 {
					t.Fatalf("result %+v err %v", res, err)
				}
				if adds, _ := f.storage.counts(); !reflect.DeepEqual(adds, []int32{2}) {
					t.Fatalf("adds %v", adds)
				}
			}
			stored, err := f.bodies.Read(1, s.Len, s.SHA)
			if err != nil || !bytes.Equal(stored, body) {
				t.Fatalf("stored body changed: %v", err)
			}
		})
	}
}

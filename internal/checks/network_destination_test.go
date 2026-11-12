package checks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

const (
	testBootID  = "4b5f6e0c-1d2e-4f3a-9b8c-7d6e5f4a3b2c"
	otherBootID = "9c8d7e6f-5a4b-4c3d-8e2f-1a0b9c8d7e6f"
)

// socketOS serves a /proc/net/tcp table, a boot ID and the process links;
// nothing else exists. globs counts the process table scans.
type socketOS struct {
	table, bootID string
	fds           []string
	links         map[string]string
	globErr       error
	globs         int
}

func (s *socketOS) install(t *testing.T) {
	t.Helper()
	withMockOS(t, &mockOS{
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/proc/net/tcp":
				return []byte(procTCPHeader + s.table), nil
			case "/proc/sys/kernel/random/boot_id":
				if s.bootID != "" {
					return []byte(s.bootID + "\n"), nil
				}
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if pattern != "/proc/*/fd/*" {
				return nil, nil
			}
			s.globs++
			return s.fds, s.globErr
		},
		readlink: func(path string) (string, error) {
			if target, ok := s.links[path]; ok {
				return target, nil
			}
			return "", os.ErrNotExist
		},
	})
}

func outboundOS(t *testing.T, table, bootID string) *socketOS {
	t.Helper()
	s := &socketOS{table: table, bootID: bootID}
	s.install(t)
	return s
}

func c2Findings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "c2_connection" {
			out = append(out, f)
		}
	}
	return out
}

// tick makes the next scan's clock reading later than any before it.
func tick() { time.Sleep(2 * time.Millisecond) }

const c2Row = "1: 010200C0:C350 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 12345\n"

// A row whose local port has a listener in the same read may be the accept
// side of a connection the listed address opened, or a process hiding its
// own connection behind a listener on its source port; the socket table
// cannot tell them apart. Both still report, but only a socket without a
// listener is stamped as an outbound destination. Only established rows
// are read.
func TestC2ConnectionStampsOutboundOnly(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{4444}}
	for _, tc := range []struct {
		name, table string
		c2, stamped int
	}{
		{"outbound", c2Row, 1, 1},
		{"inbound on wildcard listener", "0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100\n" +
			"1: 010200C0:01BB 097100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345\n", 1, 0},
		{"inbound on address listener", "0: 010200C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100\n" +
			"1: 010200C0:01BB 097100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345\n", 1, 0},
		{"listener without an inode", "0: 010200C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0\n" +
			"1: 010200C0:01BB 097100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345\n", 1, 0},
		{"listener on another address", "0: 020200C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100\n" +
			"1: 010200C0:01BB 097100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345\n", 1, 1},
		{"listener after the row", c2Row + "2: 00000000:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100\n", 1, 0},
		{"own listener on the source port", "0: 00000000:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1001 0 100\n" + c2Row, 1, 0},
		{"TIME_WAIT", "1: 010200C0:C350 097100CB:01BB 06 00000000:00000000 00:00000000 00000000 0 0 0\n", 0, 0},
		{"SYN_SENT", "1: 010200C0:C350 097100CB:01BB 02 00000000:00000000 00:00000000 00000000 1001 0 12345\n", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outboundOS(t, tc.table, testBootID)
			got := c2Findings(CheckOutboundConnections(context.Background(), cfg, nil))
			if len(got) != tc.c2 {
				t.Fatalf("c2_connection findings = %+v, want %d", got, tc.c2)
			}
			stamped := 0
			for _, f := range got {
				outbound := f.Observation != (alert.Observation{})
				if outbound {
					stamped++
				}
				if listening := strings.Contains(f.Details, "local port also listening"); listening == outbound {
					t.Fatalf("details %q with observation %+v: a listening port must be named exactly when the row is not stamped", f.Details, f.Observation)
				}
				if !outbound && f.Attribution == admission.AttributionSocketDestination {
					t.Fatalf("unstamped finding attributed as %v", f.Attribution)
				}
			}
			if stamped != tc.stamped {
				t.Fatalf("stamped findings = %d, want %d: %+v", stamped, tc.stamped, got)
			}
		})
	}
}

// A listed peer connected to a backdoor listener reports both the listener
// and the C2 address; only the outbound reading supplies a forecast.
func TestC2ConnectionInboundKeepsBackdoorListener(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{4444}}
	outboundOS(t, "0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 100\n"+
		"1: 010200C0:115C 097100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345\n", testBootID)
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	c2 := c2Findings(findings)
	if _, ok := findingForCheck(findings, "backdoor_port"); !ok || len(c2) != 1 || c2[0].Observation != (alert.Observation{}) {
		t.Fatalf("findings = %+v, want backdoor_port and one unstamped c2_connection", findings)
	}
}

func TestC2ConnectionStampsSocketObservation(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}, BackdoorPorts: []int{4444}}
	outboundOS(t, "1: 010200C0:115C 097100CB:115C 01 00000000:00000000 00:00000000 00000000 1001 0 12345\n", testBootID)
	before := time.Now()
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	after := time.Now()
	got := c2Findings(findings)
	if len(got) != 1 {
		t.Fatalf("c2_connection findings = %+v, want one", findings)
	}
	f := got[0]
	o := f.Observation
	if o.Producer != string(ProducerConnectionScan) || o.Stream != "s:"+testBootID || o.Cursor != "12345" || o.ObservedAt.Before(before) || o.ObservedAt.After(after) {
		t.Fatalf("observation = %+v, want the connection scan, this boot's socket table, inode 12345 and the scan time", o)
	}
	if f.Attribution != admission.AttributionSocketDestination {
		t.Fatalf("attribution = %v, want socket_destination", f.Attribution)
	}
	for _, want := range []string{"Local socket: 192.0.2.1:4444", "socket inode 12345", "uid 1001"} {
		if !strings.Contains(f.Details, want) {
			t.Fatalf("details %q, want %q", f.Details, want)
		}
	}
	if !strings.Contains(f.Message, "203.0.113.9:4444") {
		t.Fatalf("message %q, want the remote endpoint", f.Message)
	}
	producer, in, err := AdmissionEvidence(f)
	if err != nil || producer != ProducerConnectionScan || in.Target.Prefix().String() != "203.0.113.9/32" || in.Attribution != admission.AttributionSocketDestination {
		t.Fatalf("AdmissionEvidence = %q, %+v, %v; want the destination from the connection scan", producer, in, err)
	}
	for _, other := range findings {
		if other.Check != "c2_connection" && (other.Observation != (alert.Observation{}) || other.Attribution.Valid()) {
			t.Errorf("%s stamped %+v, %v; only the C2 check reads a destination", other.Check, other.Observation, other.Attribution)
		}
	}
}

// Without the boot or the inode the socket has no identity: the finding
// still reports, and admission refuses it for want of an observation.
func TestC2ConnectionWithoutSocketIdentity(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	for _, tc := range []struct{ name, inode, bootID string }{
		{"no boot id", "12345", ""},
		{"blank boot id", "12345", " \t"},
		{"zero inode", "0", testBootID},
		{"malformed inode", "12a45", testBootID},
		{"signed inode", "+12345", testBootID},
		{"missing inode", "", testBootID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outboundOS(t, "1: 010200C0:C350 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 "+tc.inode+"\n", tc.bootID)
			got := c2Findings(CheckOutboundConnections(context.Background(), cfg, nil))
			if len(got) != 1 {
				t.Fatalf("c2_connection findings = %+v, want one", got)
			}
			if got[0].Observation != (alert.Observation{}) || got[0].Attribution.Valid() {
				t.Fatalf("observation %+v, attribution %v; want none", got[0].Observation, got[0].Attribution)
			}
			var refusal *admission.Error
			if _, _, err := AdmissionEvidence(got[0]); !errors.As(err, &refusal) || refusal.Cause != admission.CauseNoObservation {
				t.Fatalf("AdmissionEvidence err = %v, want no_observation", err)
			}
		})
	}
}

// A later scan of the same socket names the same observation, first seen
// time included, across a restart; a socket that went away, or another
// boot, starts again.
func TestC2ConnectionKeepsFirstSeen(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var row ProducerEntry
	for _, entry := range producerTable {
		if entry.Spec.ID == ProducerConnectionScan {
			row = entry
		}
	}
	p, err := reg.Register(row.Spec)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(f alert.Finding) admission.Evidence {
		t.Helper()
		_, in, inErr := AdmissionEvidence(f)
		if inErr != nil {
			t.Fatal(inErr)
		}
		e, mintErr := p.Mint(in)
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		return e
	}
	sock := outboundOS(t, c2Row, testBootID)
	scan := func() alert.Finding {
		t.Helper()
		tick()
		got := c2Findings(CheckOutboundConnections(context.Background(), cfg, st))
		if len(got) != 1 || got[0].Observation.ObservedAt.IsZero() {
			t.Fatalf("c2_connection findings = %+v, want one with an observation", got)
		}
		return got[0]
	}
	f1 := scan()
	first := f1.Observation.ObservedAt
	f2 := scan()
	if f2.Observation != f1.Observation {
		t.Fatalf("rescan observation %+v, want %+v", f2.Observation, f1.Observation)
	}
	if e1, e2 := mint(f1), mint(f2); e1.ID() != e2.ID() || !e1.SameExceptFinding(e2) {
		t.Fatal("a rescan of the same socket minted a different record")
	}
	if err = st.Flush(); err != nil {
		t.Fatal(err)
	}
	if st, err = state.Open(dir); err != nil {
		t.Fatal(err)
	}
	if f3 := scan(); !f3.Observation.ObservedAt.Equal(first) {
		t.Fatalf("after a restart observed at %v, want %v", f3.Observation.ObservedAt, first)
	}
	sock.table = ""
	if got := c2Findings(CheckOutboundConnections(context.Background(), cfg, st)); len(got) != 0 {
		t.Fatalf("findings without the row = %+v", got)
	}
	sock.table = c2Row
	f4 := scan()
	if !f4.Observation.ObservedAt.After(first) {
		t.Fatalf("a socket seen again after it went away observed at %v, want after %v", f4.Observation.ObservedAt, first)
	}
	sock.bootID = otherBootID
	if f5 := scan(); !f5.Observation.ObservedAt.After(f4.Observation.ObservedAt) || f5.Observation.Stream != "s:"+otherBootID {
		t.Fatalf("after a reboot observation = %+v, want a new stream seen after %v", f5.Observation, f4.Observation.ObservedAt)
	}
}

// The process holding each socket is named when one is found, best effort:
// the first process found, once. The uid stays the kernel row's.
func TestC2ConnectionNamesSocketProcess(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	table := c2Row + "2: 010200C0:C351 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 23456\n"
	links := map[string]string{
		"/proc/77/fd/0":    "/dev/null",
		"/proc/77/fd/5":    "socket:[1234]",
		"/proc/4242/fd/3":  "socket:[12345]",
		"/proc/4242/exe":   "/tmp/.x/beacon\nforged",
		"/proc/4243/fd/9":  "socket:[12345]",
		"/proc/4243/exe":   "/usr/bin/other",
		"/proc/4244/fd/1":  "socket:[23456]",
		"/proc/4244/exe":   "/usr/bin/second",
		"/proc/self/fd/3":  "socket:[12345]",
		"/proc/thread/exe": "/x",
	}
	for _, tc := range []struct {
		name, want, second string
		fds                []string
	}{
		{"found", `process 4242 "/tmp/.x/beacon\nforged"`, `process 4244 "/usr/bin/second"`,
			[]string{"/proc/77/fd/0", "/proc/77/fd/5", "/proc/4242/fd/3", "/proc/4243/fd/9", "/proc/4244/fd/1"}},
		{"not found", "", "", []string{"/proc/77/fd/0", "/proc/77/fd/5"}},
		{"non-numeric process", "", "", []string{"/proc/self/fd/3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &socketOS{table: table, bootID: testBootID, fds: tc.fds, links: links}
			s.install(t)
			got := c2Findings(CheckOutboundConnections(context.Background(), cfg, nil))
			if len(got) != 2 {
				t.Fatalf("c2_connection findings = %+v, want two", got)
			}
			for i, want := range []string{tc.want, tc.second} {
				details := got[i].Details
				if !strings.Contains(details, "uid 1001") {
					t.Fatalf("details %q, want the kernel row's uid", details)
				}
				if want == "" {
					if strings.Contains(details, "process") {
						t.Fatalf("details %q, want no process", details)
					}
				} else if !strings.Contains(details, want) || strings.Count(details, "process") != 1 {
					t.Fatalf("details %q, want %s once", details, want)
				}
			}
		})
	}
}

// The process table is read at most once per scan, and only for a matched
// socket with an inode; a failed lookup never changes the finding.
func TestC2SocketProcessLookupLifecycle(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	links := map[string]string{"/proc/4242/fd/3": "socket:[12345]"}
	two := c2Row + "2: 010200C0:C351 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 23456\n"
	for _, tc := range []struct {
		name, table string
		globErr     error
		globs, c2   int
		want        string
	}{
		{"no match", "1: 010200C0:C350 0A7100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 12345\n", nil, 0, 0, ""},
		{"no inode", "1: 010200C0:C350 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 0\n", nil, 0, 1, ""},
		{"two sockets", two, nil, 1, 2, "process 4242"},
		{"glob error", c2Row, errors.New("boom"), 1, 1, ""},
		{"unreadable executable", c2Row, nil, 1, 1, "process 4242"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &socketOS{table: tc.table, bootID: testBootID, links: links, globErr: tc.globErr}
			if tc.globErr == nil {
				s.fds = []string{"/proc/4242/fd/3"}
			}
			s.install(t)
			got := c2Findings(CheckOutboundConnections(context.Background(), cfg, nil))
			if len(got) != tc.c2 || s.globs != tc.globs {
				t.Fatalf("findings %+v after %d globs, want %d findings and %d globs", got, s.globs, tc.c2, tc.globs)
			}
			for _, f := range got {
				if f.Observation.Cursor != "" && f.Observation.Cursor != "12345" && f.Observation.Cursor != "23456" {
					t.Fatalf("cursor %q changed", f.Observation.Cursor)
				}
			}
			if tc.c2 > 0 {
				d := got[0].Details
				if tc.want == "" && strings.Contains(d, "process") {
					t.Fatalf("details %q, want no process", d)
				}
				if tc.want != "" && !strings.HasSuffix(d, ", "+tc.want) {
					t.Fatalf("details %q, want to end with %q", d, tc.want)
				}
			}
		})
	}
}

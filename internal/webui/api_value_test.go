package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/processctx"
)

var utcTestZone = time.FixedZone("host", 3*3600)

// utcTestAt has a +03:00 offset and nanoseconds the copy must keep.
var utcTestAt = time.Date(2026, 9, 22, 13, 4, 5, 123456789, utcTestZone)

func encodeUTC(t *testing.T, v any) string {
	t.Helper()
	out, err := apiValue(v)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type nested struct {
	When    time.Time            `json:"when"`
	Maybe   *time.Time           `json:"maybe,omitempty"`
	List    []alert.Finding      `json:"list"`
	ByName  map[string]time.Time `json:"by_name"`
	Any     any                  `json:"any"`
	Label   string               `json:"label"`
	private time.Time
}

// Every reachable instant goes out in UTC with its nanoseconds; the value
// the handler passed in keeps its zone.
func TestUTCTimesConvertsEveryReachableTime(t *testing.T) {
	maybe := utcTestAt
	in := nested{
		When:    utcTestAt,
		Maybe:   &maybe,
		List:    []alert.Finding{{Check: "webshell", Timestamp: utcTestAt, FirstSeen: utcTestAt}},
		ByName:  map[string]time.Time{"a": utcTestAt},
		Any:     map[string]any{"items": []alert.Finding{{Timestamp: utcTestAt}}, "at": utcTestAt},
		Label:   "x",
		private: utcTestAt,
	}
	got := encodeUTC(t, in)
	if strings.Contains(got, "+03:00") {
		t.Fatalf("an offset survived: %s", got)
	}
	if strings.Count(got, "2026-09-22T10:04:05.123456789Z") != 7 {
		t.Fatalf("want 7 UTC instants with nanoseconds: %s", got)
	}
	if in.When.Location() != utcTestZone || in.Maybe.Location() != utcTestZone || in.List[0].Timestamp.Location() != utcTestZone ||
		in.ByName["a"].Location() != utcTestZone || in.private.Location() != utcTestZone {
		t.Fatal("the input was modified")
	}
	if items := in.Any.(map[string]any)["items"].([]alert.Finding); items[0].Timestamp.Location() != utcTestZone {
		t.Fatal("a slice inside an interface was modified in place")
	}
}

// The copy keeps the JSON shape: a typed nil pointer stays a nil pointer,
// values stay values, and an empty list or map goes out empty, never null.
func TestUTCTimesKeepsTheShape(t *testing.T) {
	var nilFindings []alert.Finding
	var nilProcess *processctx.ProcessContext
	body := map[string]any{"none": nilFindings, "empty": []alert.Finding{}, "proc": nilProcess, "n": 3, "s": "x"}
	got := encodeUTC(t, body)
	want := `{"empty":[],"n":3,"none":[],"proc":null,"s":"x"}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

type listsAndMaps struct {
	Names   []string          `json:"names"`
	Counts  map[string]int    `json:"counts"`
	Nested  []listsAndMaps    `json:"nested"`
	Hidden  []string          `json:"hidden,omitempty"`
	Raw     json.RawMessage   `json:"raw"`
	Bytes   []byte            `json:"bytes"`
	Unknown *int              `json:"unknown"`
	ByKey   map[string][]bool `json:"by_key"`
}

// An empty list is [] and an empty map {}, however deep. Bytes and raw JSON
// keep their meaning, an omitted list stays omitted, and a nil pointer, which
// means "unknown", stays null.
func TestUTCTimesSendsEmptyCollectionsNotNull(t *testing.T) {
	in := listsAndMaps{Nested: []listsAndMaps{{}}, ByKey: map[string][]bool{"a": nil}}
	got := encodeUTC(t, map[string]any{"v": in, "list": []int(nil), "map": map[string]string(nil)})
	want := `{"list":[],"map":{},"v":{"names":[],"counts":{},"nested":[{"names":[],"counts":{},"nested":[],"raw":null,"bytes":null,"unknown":null,"by_key":{}}],` +
		`"raw":null,"bytes":null,"unknown":null,"by_key":{"a":[]}}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if in.Names != nil || in.Nested[0].Names != nil || in.ByKey["a"] != nil {
		t.Fatal("the input was modified")
	}
}

// A process chain is a recursive type; each parent's start time converts.
func TestUTCTimesFollowsProcessParents(t *testing.T) {
	start := utcTestAt
	proc := &processctx.ProcessContext{PID: 2, StartedAt: &start, Parent: &processctx.ProcessContext{PID: 1, StartedAt: &start}}
	got := encodeUTC(t, alert.Finding{Timestamp: utcTestAt, Process: proc})
	if strings.Contains(got, "+03:00") || strings.Count(got, "10:04:05.123456789Z") != 3 {
		t.Fatalf("got %s", got)
	}
	if proc.StartedAt.Location() != utcTestZone || proc.Parent.StartedAt.Location() != utcTestZone {
		t.Fatal("the process chain was modified")
	}
}

type loop struct {
	When time.Time `json:"when"`
	Next *loop     `json:"next"`
}

// A cycle cannot be copied; it is refused instead of recursing forever.
func TestUTCTimesRefusesACycle(t *testing.T) {
	a := &loop{When: utcTestAt}
	a.Next = a
	if _, err := apiValue(a); !errors.Is(err, errResponseTooDeep) {
		t.Fatalf("err = %v, want errResponseTooDeep", err)
	}
}

// Incident renders its severity with its own marshaler; the copy must keep
// that and still convert the incident's times.
func TestUTCTimesKeepsCustomMarshalers(t *testing.T) {
	inc := incident.Incident{ID: "inc_1", Severity: alert.Critical, CreatedAt: utcTestAt, UpdatedAt: utcTestAt}
	got := encodeUTC(t, []incident.Incident{inc})
	if !strings.Contains(got, `"severity":"CRITICAL"`) || strings.Contains(got, "+03:00") {
		t.Fatalf("got %s", got)
	}
}

// Values that cannot hold a time are passed through untouched.
func TestAPIValuePassesPlainValuesThrough(t *testing.T) {
	in := []string{"a", "b"}
	out, err := apiValue(in)
	if err != nil {
		t.Fatal(err)
	}
	if &out.([]string)[0] != &in[0] {
		t.Fatal("a time-free slice was copied")
	}
}

// writeJSON is where the rule applies, so every route follows it.
func TestWriteJSONSendsUTCTimes(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]any{"at": utcTestAt})
	if got := strings.TrimSpace(w.Body.String()); got != `{"at":"2026-09-22T10:04:05.123456789Z"}` {
		t.Fatalf("got %s", got)
	}
}

// historyPage is a full history page: 5000 findings with a relay breakdown
// and a process chain, the largest body the API sends.
func historyPage() map[string]any {
	start := utcTestAt
	findings := make([]historyFinding, 5000)
	for i := range findings {
		findings[i] = historyFinding{Finding: alert.Finding{
			Check: "webshell", Message: "shell", Timestamp: utcTestAt, FirstSeen: utcTestAt,
			RelayBreakdown: []alert.RelayScriptHit{{ScriptKey: "a", Hits: 1, LastSeen: utcTestAt}},
			Process:        &processctx.ProcessContext{PID: 2, StartedAt: &start, Parent: &processctx.ProcessContext{PID: 1}},
		}, Account: "alice"}
	}
	return map[string]any{"items": findings, "total": 5000}
}

func BenchmarkHistoryPageEncode(b *testing.B) {
	page := historyPage()
	b.ReportAllocs()
	for b.Loop() {
		_ = json.NewEncoder(io.Discard).Encode(page)
	}
}

func BenchmarkHistoryPageUTCAndEncode(b *testing.B) {
	page := historyPage()
	b.ReportAllocs()
	for b.Loop() {
		out, _ := apiValue(page)
		_ = json.NewEncoder(io.Discard).Encode(out)
	}
}

type hiddenTimes struct {
	When time.Time `json:"when"`
}

type embedsHidden struct {
	hiddenTimes
	Name string `json:"name"`
}

// encoding/json promotes the fields of an unexported embedded struct, but
// reflection cannot set them, so its times would go out in the host zone.
// apiValue refuses such a type instead of sending them unconverted.
func TestAPIValueRefusesUnreachableEmbeddedTimes(t *testing.T) {
	_, err := apiValue(embedsHidden{hiddenTimes: hiddenTimes{When: utcTestAt}, Name: "x"})
	if !errors.Is(err, errUnreachableField) {
		t.Fatalf("err = %v, want errUnreachableField", err)
	}
}

package responsereplay_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
	"github.com/pidginhost/csm/internal/responsereplay"
)

// jsonShape maps each JSON name of t to its kind, following pointers, so the
// mirror's pointer fields for required keys compare equal to plain fields.
func jsonShape(t reflect.Type) map[string]reflect.Kind {
	shape := map[string]reflect.Kind{}
	for _, f := range reflect.VisibleFields(t) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		shape[name] = ft.Kind()
	}
	return shape
}

// The reader decodes into a private copy of the audit schema, because
// importing alert here would make the firewall cross-check tests an import
// cycle. This test is what keeps the copy honest.
func TestWireMirrorMatchesAuditSchema(t *testing.T) {
	for name, real := range map[string]reflect.Type{
		"event":   reflect.TypeFor[alert.AuditEvent](),
		"process": reflect.TypeFor[processctx.ProcessContext](),
	} {
		if got, want := jsonShape(responsereplay.WireFields[name]), jsonShape(real); !reflect.DeepEqual(got, want) {
			t.Errorf("%s mirror drifted:\n got %v\nwant %v", name, got, want)
		}
	}
}

// populate sets every exported field of v, nested structs included.
func populate(v reflect.Value, depth int) {
	switch v.Kind() {
	case reflect.Pointer:
		if depth > 2 {
			return
		}
		v.Set(reflect.New(v.Type().Elem()))
		populate(v.Elem(), depth+1)
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				populate(v.Field(i), depth)
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		populate(v.Index(0), depth)
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Bool:
		v.SetBool(true)
	}
}

func writeLine(t *testing.T, line []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stream.jsonl")
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every field of the real schema, nested process parents included, reads
// back; an unknown key beside any of them refuses the row.
func TestReaderAcceptsEveryAuditField(t *testing.T) {
	var e alert.AuditEvent
	populate(reflect.ValueOf(&e).Elem(), 0)
	e.V = alert.AuditSchemaVersion
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := responsereplay.ReadFindings(writeLine(t, raw))
	if err != nil {
		t.Fatalf("full audit row refused: %v", err)
	}
	got := rec.Findings[0]
	if got.Check != e.Check || got.Severity != e.Severity || got.Message != e.Message || got.Details != e.Details ||
		got.FindingID != e.FindingID || !got.At.Equal(e.Timestamp) || got.Ordinal != 1 {
		t.Fatalf("replay fields lost: %+v", got)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	var objects []map[string]any
	for obj := generic; obj != nil; {
		objects = append(objects, obj)
		next, _ := obj["process"].(map[string]any)
		if next == nil {
			next, _ = obj["parent"].(map[string]any)
		}
		obj = next
	}
	if len(objects) < 3 {
		t.Fatalf("fixture lacks nested process objects: %d", len(objects))
	}
	for depth, obj := range objects {
		for key := range obj {
			sibling := key + "_unknown"
			obj[sibling] = "x"
			line, err := json.Marshal(generic)
			delete(obj, sibling)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := responsereplay.ReadFindings(writeLine(t, line)); err == nil {
				t.Errorf("unknown sibling of %q at depth %d accepted", key, depth)
			}
		}
	}
}

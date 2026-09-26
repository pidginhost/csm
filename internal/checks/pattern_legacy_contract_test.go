package checks

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const legacyPatternTime = "[26/Sep/2026:10:00:00 +0300]"

func TestPatternLegacyParserContract(t *testing.T) {
	// Characterization: these pass on the unchanged base, before the new parser.
	target := "/" + strings.Repeat("a", 5000)
	for _, tc := range []struct {
		limit int
		want  string
	}{
		{4096, target[:4096]}, {8192, target}, {0, ""},
	} {
		line := `192.0.2.1 - - ` + legacyPatternTime + ` "GET ` + target + ` HTTP/1.1" 200 1 "-" "UA" "example.com:443" "203.0.113.7"`
		got, ok := parseAccessLogRecordWithURILimit(line, tc.limit)
		stamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", strings.Trim(legacyPatternTime, "[]"))
		if err != nil {
			t.Fatal(err)
		}
		want := accessLogRecord{RemoteIP: "192.0.2.1", Time: stamp, Method: "GET", URI: tc.want, Status: 200, UserAgent: "UA", XFF: "203.0.113.7"}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("legacy limit %d: ok=%v %+v", tc.limit, ok, got)
		}
		if tc.limit == 4096 {
			def, defOK := parseAccessLogRecord(line)
			if defOK != ok || !reflect.DeepEqual(def, got) {
				t.Fatal("default parser changed")
			}
		}
	}
	got, ok := parseAccessLogRecord(`192.0.2.1 - - ` + legacyPatternTime + ` "GET / HTTP/1.1" 200 1 "-" "UA \"quoted\""`)
	if !ok || got.UserAgent != `UA \` {
		t.Fatalf("legacy quote behavior changed: ok=%v ua=%q", ok, got.UserAgent)
	}
}

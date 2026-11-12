package firewall

import (
	"reflect"
	"testing"
)

func TestParseLocalPortLocks(t *testing.T) {
	got, err := ParseLocalPortLocks([]string{"8080:www-data,stalwart", " 9000 : nobody "})
	if err != nil {
		t.Fatal(err)
	}
	want := []LocalPortLock{{Port: 8080, Users: []string{"www-data", "stalwart"}}, {Port: 9000, Users: []string{"nobody"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got, err := ParseLocalPortLocks(nil); err != nil || len(got) != 0 {
		t.Fatalf("nil = %v, %v", got, err)
	}
	for _, bad := range [][]string{
		{"8080"}, {"0:x"}, {"70000:x"}, {"8080:"}, {"x:www-data"}, {"8080:bad user"}, {"8080:a,,b"},
		{"8080:a", "8080:b"},
	} {
		if _, err := ParseLocalPortLocks(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

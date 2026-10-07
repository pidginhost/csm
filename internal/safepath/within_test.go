package safepath

import "testing"

func TestWithin(t *testing.T) {
	cases := []struct {
		path, base string
		want       bool
	}{
		{"/home/alice/public_html/x.php", "/home/alice", true},
		{"/home/alice", "/home/alice", true},
		{"/home/alice/", "/home/alice", true},
		{"/home/alice", "/home/alice/", true},
		{"/home/alicebob/x", "/home/alice", false},
		{"/home/alice/../bob/x", "/home/alice", false},
		{"/home/alice/sub/../x", "/home/alice", true},
		{"/etc/passwd", "/", true},
		{"relative/x", "/", false},
		{"/home", "/home/alice", false},
		{"home/alice/x", "home/alice", true},
		{"", "/home/alice", false},
	}
	for _, c := range cases {
		if got := Within(c.path, c.base); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.path, c.base, got, c.want)
		}
	}
}

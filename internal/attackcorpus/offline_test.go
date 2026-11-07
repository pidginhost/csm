package attackcorpus

import (
	"net/http"
	"strings"
	"testing"
)

func TestOfflineTransportCountsAndFails(t *testing.T) {
	before := http.DefaultTransport
	t.Run("offline", func(t *testing.T) {
		n := Offline(t)
		if resp, err := http.Get("http://192.0.2.10/checksums"); err == nil {
			_ = resp.Body.Close()
			t.Fatal("GET through the default client succeeded")
		}
		client := &http.Client{}
		if resp, err := client.Post("https://198.51.100.20/api", "text/plain", strings.NewReader("body")); err == nil {
			_ = resp.Body.Close()
			t.Fatal("POST through a client with no transport succeeded")
		}
		if got := n.Load(); got != 2 {
			t.Errorf("counted %d attempts, want 2", got)
		}
	})
	if http.DefaultTransport != before {
		t.Error("the default transport was not restored")
	}
}

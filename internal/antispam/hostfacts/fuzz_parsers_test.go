package hostfacts

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countedReader struct {
	io.Reader
	read int
}

func FuzzResolve(f *testing.F) {
	for _, target := range []string{"file", "file/", "dir/", "dir/../file", "missing", "link", "."} {
		f.Add(target)
	}
	f.Fuzz(func(t *testing.T, target string) {
		// Keep every generated lookup within the disposable fixture.
		if len(target) > 1024 || !filepath.IsLocal(target) {
			return
		}
		d := t.TempDir()
		write(t, filepath.Join(d, "file"), "")
		mkdir(t, filepath.Join(d, "dir"))
		link := filepath.Join(d, "link")
		if err := os.Symlink(target, link); err != nil {
			return
		}
		kernel, kernelErr := os.Stat(link)
		final, _, walkErr := resolve(link)
		if (kernelErr == nil) != (walkErr == nil) {
			t.Fatalf("kernel lookup: %v; resolver: %v", kernelErr, walkErr)
		}
		if kernelErr == nil {
			got, err := os.Lstat(final)
			if err != nil || !os.SameFile(kernel, got) {
				t.Fatalf("resolved object differs from the kernel lookup: %v", err)
			}
		}
	})
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += n
	return n, err
}

func FuzzReadPingReply(f *testing.F) {
	for _, reply := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npong\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npong\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", 64<<10) + "\r\n\r\npong",
		"HTTP/1.1 200 OK\r\nContent-Length: reply-marker\r\n\r\n",
		"", "reply-marker\r\n\r\n",
	} {
		f.Add(reply)
	}
	f.Fuzz(func(t *testing.T, reply string) {
		r := &countedReader{Reader: strings.NewReader(reply)}
		err := readPingReply(io.NopCloser(r))
		if r.read > maxPingReply+1 {
			t.Fatalf("read %d bytes beyond the reply budget", r.read)
		}
		if err != nil {
			message := err.Error()
			switch message {
			case "rspamd /ping returned an invalid HTTP response", "rspamd /ping reply could not be read",
				"rspamd /ping reply is too large", "rspamd /ping did not answer pong":
			default:
				if !strings.HasPrefix(message, "rspamd /ping returned HTTP ") || len(message) > 30 {
					t.Fatalf("unexpected error text: %q", message)
				}
			}
		}
	})
}

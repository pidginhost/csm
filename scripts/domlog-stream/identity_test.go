package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

// twoSiteRun converts two sites whose single log copies are at the given
// paths, relative to a fresh directory that already holds the named files.
func twoSiteRun(t *testing.T, files map[string][]byte, logA, logB string) error {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return runInventory(t, dir, period+`"sites":[
	  {"name":"a.example","account":"acct1","aliases":["a.example"],"logs":["`+filepath.Join(dir, logA)+`"]},
	  {"name":"b.example","account":"acct2","aliases":["b.example"],"logs":["`+filepath.Join(dir, logB)+`"]}]}`)
}

func runInventory(t *testing.T, dir, inventory string) error {
	t.Helper()
	salt, inv := filepath.Join(dir, "salt"), filepath.Join(dir, "inventory.json")
	for path, data := range map[string][]byte{salt: bytes.Repeat([]byte{0x42}, 32), inv: []byte(inventory)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return run([]string{"convert", "--salt-file", salt, "--inventory", inv, "--out", filepath.Join(dir, "r.jsonl.gz"),
		"--volume-out", filepath.Join(dir, "v.jsonl.gz"), "--manifest", filepath.Join(dir, "m.json")}, io.Discard, testEnv())
}

func TestInventoryIdentityAndCollisionRefusal(t *testing.T) {
	one := []byte(line("192.0.2.10", "19:00:05", "GET /?p=1 HTTP/1.1", "200", "") + "\n")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(one); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	t.Run("cross-site alias", func(t *testing.T) {
		for name, sites := range map[string]string{
			"shared alias": `{"name":"a.example","account":"a","aliases":["a.example","shared.example"],"logs":["x"]},
			  {"name":"b.example","account":"b","aliases":["b.example","shared.example"],"logs":["y"]}`,
			"alias names another site": `{"name":"a.example","account":"a","aliases":["a.example","b.example"],"logs":["x"]},
			  {"name":"b.example","account":"b","aliases":["b.example"],"logs":["y"]}`,
			"repeated alias": `{"name":"a.example","account":"a","aliases":["a.example","a.example"],"logs":["x"]}`,
		} {
			if _, err := parseInventory([]byte(period + `"sites":[` + sites + `]}`)); !errors.Is(err, errInventory) {
				t.Errorf("%s: err = %v, want errInventory", name, err)
			}
		}
	})
	t.Run("hard link", func(t *testing.T) {
		dir := t.TempDir()
		a := filepath.Join(dir, "a.log")
		if err := os.WriteFile(a, one, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(a, filepath.Join(dir, "b.log")); err != nil {
			t.Fatal(err)
		}
		err := runInventory(t, dir, period+`"sites":[
		  {"name":"a.example","account":"acct1","aliases":["a.example"],"logs":["`+a+`"]},
		  {"name":"b.example","account":"acct2","aliases":["b.example"],"logs":["`+filepath.Join(dir, "b.log")+`"]}]}`)
		if !errors.Is(err, errInputIdentity) {
			t.Fatalf("hard-linked copy: err = %v, want errInputIdentity", err)
		}
	})
	t.Run("path alias", func(t *testing.T) {
		dir := t.TempDir()
		a := filepath.Join(dir, "a.log")
		if err := os.WriteFile(a, one, 0o600); err != nil {
			t.Fatal(err)
		}
		err := runInventory(t, dir, period+`"sites":[
		  {"name":"a.example","account":"acct1","aliases":["a.example"],"logs":["`+a+`"]},
		  {"name":"b.example","account":"acct2","aliases":["b.example"],"logs":["`+dir+`/./a.log"]}]}`)
		if !errors.Is(err, errInputIdentity) {
			t.Fatalf("same file by another path: err = %v, want errInputIdentity", err)
		}
	})
	t.Run("identical decompressed copies", func(t *testing.T) {
		if err := twoSiteRun(t, map[string][]byte{"a.log": one, "b.log.gz": gz.Bytes()}, "a.log", "b.log.gz"); !errors.Is(err, errInputIdentity) {
			t.Fatalf("plain and gzip copy of one log: err = %v, want errInputIdentity", err)
		}
	})
	t.Run("empty copies are distinct", func(t *testing.T) {
		if err := twoSiteRun(t, map[string][]byte{"a.log": nil, "b.log": nil}, "a.log", "b.log"); err != nil {
			t.Fatalf("two empty copies refused: %v", err)
		}
	})
	t.Run("referer hosts come only from the inventory", func(t *testing.T) {
		ref := line("192.0.2.10", "19:00:05", "GET /?p=1 HTTP/1.1", "200", "")
		ref = strings.Replace(ref, `"-" "Mozilla/5.0"`, `"https://WWW.Example.COM./x" "Mozilla/5.0"`, 1)
		for aliases, want := range map[string]uint8{
			`["example.com"]`:                   crawlreplay.RefCrossSite,
			`["example.com","www.example.com"]`: crawlreplay.RefSameSite,
		} {
			inv, err := parseInventory([]byte(period + `"sites":[{"name":"example.com","account":"a","aliases":` + aliases + `,"logs":["x"]}]}`))
			if err != nil {
				t.Fatal(err)
			}
			rec, ok := checks.ParseCrawlLogLine(ref, inv.Sites[0].Aliases)
			if !ok {
				t.Fatal("fixture did not parse")
			}
			c := newConverter(inv, nil, pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, testNow)
			sm := crawlreplay.SiteManifest{Labels: map[string]int64{}}
			if row, _ := c.row(inv.Sites[0], &sm, rec, 0, 1); row.Referer != want {
				t.Errorf("aliases %s: Referer class %d, want %d", aliases, row.Referer, want)
			}
		}
	})
}

// changingFile reports a different size after it has been read, as a log
// that is still being written would.
type changingFile struct {
	logFile
	stats int
}

func (c *changingFile) Stat() (os.FileInfo, error) {
	c.stats++
	info, err := c.logFile.Stat()
	if c.stats > 1 && err == nil {
		return grownInfo{info}, nil
	}
	return info, err
}

type grownInfo struct{ os.FileInfo }

func (g grownInfo) Size() int64 { return g.FileInfo.Size() + 1 }

func TestInputSnapshotsMustBeStable(t *testing.T) {
	dir := t.TempDir()
	one := []byte(line("192.0.2.10", "19:00:05", "GET /?p=1 HTTP/1.1", "200", "") + "\n")
	regular := filepath.Join(dir, "a.log")
	if err := os.WriteFile(regular, one, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		want error
	}{
		"directory": {dir, errInputIdentity},
		"fifo":      {fifo, errInputIdentity},
		"symlink":   {link, errInput},
	} {
		inv, err := parseInventory([]byte(period + `"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["` + tc.path + `"]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		c := newConverter(inv, nil, pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, testNow)
		if _, _, _, err := c.convertSite(inv.Sites[0], io.Discard); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	inv, err := parseInventory([]byte(period + `"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["` + regular + `"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := newConverter(inv, nil, pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, testNow)
	c.open = func(path string) (logFile, error) {
		f, err := openLog(path)
		if err != nil {
			return nil, err
		}
		return &changingFile{logFile: f}, nil
	}
	if _, _, _, err := c.convertSite(inv.Sites[0], io.Discard); !errors.Is(err, errInputIdentity) {
		t.Fatalf("copy that changed while read: err = %v, want errInputIdentity", err)
	}
}

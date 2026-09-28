package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
	return convertBundle(t, dir, "r", inventory, testEnv())
}

// convertBundle converts one inventory into outputs named after bundle,
// sharing the directory's salt and identity registry with other bundles.
func convertBundle(t *testing.T, dir, bundle, inventory string, e env) error {
	t.Helper()
	salt, inv := filepath.Join(dir, "salt"), filepath.Join(dir, bundle+".inventory.json")
	if _, err := os.Stat(salt); err != nil {
		if err = os.WriteFile(salt, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(inv, []byte(inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	return run([]string{"convert", "--salt-file", salt, "--registry", filepath.Join(dir, "registry.json"), "--inventory", inv,
		"--out", filepath.Join(dir, bundle+".records.jsonl.gz"), "--volume-out", filepath.Join(dir, bundle+".volume.jsonl.gz"),
		"--manifest", filepath.Join(dir, bundle+".manifest.json")}, io.Discard, e)
}

// prefixDigest gives every value of one pseudonym kind the same leading
// bytes and keeps the rest of the real digest, forcing collisions.
func prefixDigest(kind string) func(string, []byte) [sha256.Size]byte {
	salt := bytes.Repeat([]byte{0x42}, 32)
	return func(k string, v []byte) [sha256.Size]byte {
		d := saltedDigest(salt, k, v)
		if k == kind {
			copy(d[:8], "collide!")
		}
		return d
	}
}

func twoSites(dir string) string {
	return period + `"sites":[
	  {"name":"a.example","account":"acct1","aliases":["a.example"],"logs":["` + filepath.Join(dir, "a.log") + `"]},
	  {"name":"b.example","account":"acct2","aliases":["b.example"],"logs":["` + filepath.Join(dir, "b.log") + `"]}]}`
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
	t.Run("pseudonym collisions", func(t *testing.T) {
		for _, kind := range []string{"domain", "account", "crawl-key", "crawl-binding"} {
			t.Run(kind, func(t *testing.T) {
				dir := t.TempDir()
				for name, peer := range map[string]string{"a.log": "192.0.2.10", "b.log": "192.0.2.11"} {
					data := line(peer, "19:00:05", "GET /c/?filter_a=1 HTTP/1.1", "200", "") + "\n"
					if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				e := testEnv()
				e.digest = prefixDigest(kind)
				if err := convertBundle(t, dir, "r", twoSites(dir), e); !errors.Is(err, errCollision) {
					t.Fatalf("colliding %s pseudonyms: err = %v, want errCollision", kind, err)
				}
				for _, out := range []string{"r.records.jsonl.gz", "r.volume.jsonl.gz", "r.manifest.json"} {
					if _, err := os.Stat(filepath.Join(dir, out)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("refused conversion published %s", out)
					}
				}
			})
		}
	})
	t.Run("collisions across bundles sharing a salt", func(t *testing.T) {
		dir := t.TempDir()
		for name, peer := range map[string]string{"a.log": "192.0.2.10", "b.log": "192.0.2.11", "a2.log": "192.0.2.12"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(line(peer, "19:00:05", "GET / HTTP/1.1", "200", "")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		one := func(site, account, log string) string {
			return period + `"sites":[{"name":"` + site + `","account":"` + account + `","aliases":["` + site + `"],"logs":["` + filepath.Join(dir, log) + `"]}]}`
		}
		e := testEnv()
		e.digest = prefixDigest("domain")
		if err := convertBundle(t, dir, "first", one("a.example", "acct1", "a.log"), e); err != nil {
			t.Fatal(err)
		}
		if err := convertBundle(t, dir, "again", one("a.example", "acct1", "a2.log"), e); err != nil {
			t.Fatalf("the same site in a later bundle was refused: %v", err)
		}
		if err := convertBundle(t, dir, "second", one("b.example", "acct1", "b.log"), e); !errors.Is(err, errCollision) {
			t.Fatalf("a second site under the first site's pseudonym: err = %v, want errCollision", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "registry.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"a.example", "b.example", "acct1"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatalf("registry holds the raw name %q", private)
			}
		}
	})
	t.Run("registry must belong to the salt and stay private", func(t *testing.T) {
		for name, prepare := range map[string]func(t *testing.T, registry string){
			"world readable": func(t *testing.T, registry string) {
				if err := os.WriteFile(registry, []byte(`{"format_version":1,"salt_fingerprint":"`+saltFingerprint(bytes.Repeat([]byte{0x42}, 32))+`","names":{}}`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			"other salt": func(t *testing.T, registry string) {
				if err := os.WriteFile(registry, []byte(`{"format_version":1,"salt_fingerprint":"000000000000","names":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			"malformed": func(t *testing.T, registry string) {
				if err := os.WriteFile(registry, []byte(`{"format_version":1,"names":null}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			"symlink": func(t *testing.T, registry string) {
				target := registry + ".target"
				if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, registry); err != nil {
					t.Fatal(err)
				}
			},
			"busy": func(t *testing.T, registry string) {
				lock, err := os.OpenFile(registry+".lock", os.O_CREATE|os.O_RDWR, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { lock.Close() })
				if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "a.log"), one, 0o600); err != nil {
					t.Fatal(err)
				}
				prepare(t, filepath.Join(dir, "registry.json"))
				inv := period + `"sites":[{"name":"a.example","account":"acct1","aliases":["a.example"],"logs":["` + filepath.Join(dir, "a.log") + `"]}]}`
				if err := convertBundle(t, dir, "r", inv, testEnv()); !errors.Is(err, errRegistry) {
					t.Fatalf("err = %v, want errRegistry", err)
				}
			})
		}
	})
	t.Run("distinct names stay distinct", func(t *testing.T) {
		dir := t.TempDir()
		var sites []string
		for i := range 40 {
			name := "site" + twoDigits(i) + ".example"
			path := filepath.Join(dir, name+".log")
			if err := os.WriteFile(path, []byte(line("192.0.2."+twoDigits(i+10), "19:00:05", "GET / HTTP/1.1", "200", "")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			sites = append(sites, `{"name":"`+name+`","account":"acct`+twoDigits(i)+`","aliases":["`+name+`"],"logs":["`+path+`"]}`)
		}
		if err := convertBundle(t, dir, "r", period+`"sites":[`+strings.Join(sites, ",")+`]}`, testEnv()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "r.manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := crawlreplay.DecodeManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, s := range m.Sites {
			seen[s.Site], seen[s.Account] = true, true
		}
		if len(seen) != 80 {
			t.Fatalf("40 sites and accounts produced %d distinct pseudonyms, want 80", len(seen))
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
			c := newConverter(osFS{}, inv, nil, newPseudonyms(bytes.Repeat([]byte{0x42}, 32), nil), testNow)
			sm := crawlreplay.SiteManifest{Labels: map[string]int64{}}
			if row, _, _ := c.row(inv.Sites[0], &sm, rec, 0, 1); row.Referer != want {
				t.Errorf("aliases %s: Referer class %d, want %d", aliases, row.Referer, want)
			}
		}
	})
}

// changingFile reports a different size after it has been read, as a log
// that is still being written would.
type changingFile struct {
	file
	stats int
}

func (c *changingFile) Stat() (os.FileInfo, error) {
	c.stats++
	info, err := c.file.Stat()
	if c.stats > 1 && err == nil {
		return grownInfo{info}, nil
	}
	return info, err
}

type grownInfo struct{ os.FileInfo }

type changingFS struct{ osFS }

func (changingFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	f, err := osFS{}.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &changingFile{file: f}, nil
}

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
		c := newConverter(osFS{}, inv, nil, newPseudonyms(bytes.Repeat([]byte{0x42}, 32), nil), testNow)
		if _, _, _, err := c.convertSite(inv.Sites[0], io.Discard); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	inv, err := parseInventory([]byte(period + `"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["` + regular + `"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := newConverter(changingFS{}, inv, nil, newPseudonyms(bytes.Repeat([]byte{0x42}, 32), nil), testNow)
	if _, _, _, err := c.convertSite(inv.Sites[0], io.Discard); !errors.Is(err, errInputIdentity) {
		t.Fatalf("copy that changed while read: err = %v, want errInputIdentity", err)
	}
}

func TestInputSnapshotRefusesRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.log")
	data := []byte(strings.Repeat("original line\n", maxLine))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	c := newConverter(osFS{}, nil, nil, newPseudonyms(nil, nil), testNow)
	changed := false
	err = c.readInput(path, &crawlreplay.Input{}, func(logLine) error {
		if changed {
			return nil
		}
		changed = true
		// Replace both buffered and unread bytes without changing the size
		// or mtime, as a timestamp-preserving copy can do.
		replacement := bytes.ReplaceAll(data, []byte("original"), []byte("modified"))
		if writeErr := os.WriteFile(path, replacement, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if timeErr := os.Chtimes(path, before.ModTime(), before.ModTime()); timeErr != nil {
			t.Fatal(timeErr)
		}
		return nil
	})
	if !changed || !errors.Is(err, errInputIdentity) {
		t.Fatalf("same-size rewrite with restored mtime: changed=%v err=%v, want errInputIdentity", changed, err)
	}
}

type appendingLog struct {
	file
	writer *os.File
	reads  int
	bytes  int64
}

func (f *appendingLog) Read(p []byte) (int, error) {
	f.reads++
	// Stop appending eventually so a reader that chases EOF fails the
	// assertion instead of hanging the test.
	if f.reads <= 4 {
		if _, err := f.writer.WriteString("another line\n"); err != nil {
			return 0, err
		}
	}
	n, err := f.file.Read(p)
	f.bytes += int64(n)
	return n, err
}

// appendingFS opens every file as an appendingLog.
type appendingFS struct {
	osFS
	writer *os.File
	opened *appendingLog
}

func (a *appendingFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	f, err := a.osFS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	a.opened = &appendingLog{file: f, writer: a.writer}
	return a.opened, nil
}

func TestInputSnapshotBoundsGrowingRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "example.log")
	data := []byte("original line\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	fsys := &appendingFS{writer: w}
	c := newConverter(fsys, nil, nil, newPseudonyms(nil, nil), testNow)
	err = c.readInput(path, &crawlreplay.Input{}, func(logLine) error { return nil })
	if !errors.Is(err, errInputIdentity) {
		t.Fatalf("growing copy: err=%v, want errInputIdentity", err)
	}
	if fsys.opened.bytes != int64(len(data)) {
		t.Fatalf("read %d bytes from a %d-byte snapshot while it grew", fsys.opened.bytes, len(data))
	}
}

func TestCollisionUsesWholeDigest(t *testing.T) {
	for _, kind := range []string{"domain", "account", "crawl-key", "crawl-binding", "crawl-episode"} {
		t.Run(kind, func(t *testing.T) {
			ps := newPseudonyms(nil, func(_ string, value []byte) [sha256.Size]byte {
				var d [sha256.Size]byte
				d[len(d)-1] = value[0]
				return d
			})
			n := 8
			if kind == "domain" || kind == "account" {
				n = 3
			}
			if _, _, err := ps.name(kind, []byte("a"), n); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ps.name(kind, []byte("a"), n); err != nil {
				t.Fatalf("same value refused: %v", err)
			}
			if _, _, err := ps.name(kind, []byte("b"), n); !errors.Is(err, errCollision) {
				t.Fatalf("different digest suffix accepted: %v", err)
			}
		})
	}
}

func TestCrossBundleIdentityKinds(t *testing.T) {
	for _, kind := range []string{"account", "crawl-episode"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.log")
			writeLog := func(peer, request string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(line(peer, "19:00:05", request, "200", "")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			inventory := func(account string) string {
				return period + `"sites":[{"name":"a.example","account":"` + account + `","aliases":["a.example"],"logs":["` + path + `"]}]}`
			}
			e := testEnv()
			e.digest = prefixDigest(kind)
			convert := func(bundle, account, episode string) error {
				if kind != "crawl-episode" {
					return convertBundle(t, dir, bundle, inventory(account), e)
				}
				// Use the actual CLI entry with labels so episode reservations are persisted.
				salt, inv, labels := filepath.Join(dir, "salt"), filepath.Join(dir, bundle+".inventory.json"), filepath.Join(dir, bundle+".labels.json")
				for p, b := range map[string][]byte{
					salt: bytes.Repeat([]byte{0x42}, 32), inv: []byte(inventory(account)),
					labels: []byte(`{"labels":[{"site":"a.example","from":"2026-09-26T19:00:00Z","to":"2026-09-26T20:00:00Z","label":"attack","episode":"` + episode + `"}]}`),
				} {
					if err := os.WriteFile(p, b, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return run([]string{"convert", "--salt-file", salt, "--registry", filepath.Join(dir, "registry.json"), "--inventory", inv, "--labels", labels,
					"--out", filepath.Join(dir, bundle+".records.jsonl.gz"), "--volume-out", filepath.Join(dir, bundle+".volume.jsonl.gz"), "--manifest", filepath.Join(dir, bundle+".manifest.json")}, io.Discard, e)
			}
			writeLog("192.0.2.10", "GET /c/?filter_a=1 HTTP/1.1")
			if err := convert("first", "acct1", "first"); err != nil {
				t.Fatal(err)
			}
			if err := convert("repeat", "acct1", "first"); err != nil {
				t.Fatalf("same identities refused: %v", err)
			}
			before, err := os.ReadFile(filepath.Join(dir, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			account, episode := "acct1", "first"
			switch kind {
			case "account":
				account = "acct2"
			case "crawl-episode":
				episode = "second"
			}
			if err = convert("collision", account, episode); !errors.Is(err, errCollision) {
				t.Fatalf("cross-bundle %s collision: %v", kind, err)
			}
			after, err := os.ReadFile(filepath.Join(dir, "registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("collision changed registry")
			}
			for _, name := range []string{"collision.records.jsonl.gz", "collision.volume.jsonl.gz", "collision.manifest.json"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("collision published %s", name)
				}
			}
		})
	}
}

// Key and binding pseudonyms stay out of the registry: one entry per client
// and pattern ever converted would grow it with all traffic.
func TestRegistryHoldsSiteAccountAndEpisodeNames(t *testing.T) {
	dir := t.TempDir()
	for name, peer := range map[string]string{"a.log": "192.0.2.10", "b.log": "192.0.2.11"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(line(peer, "19:00:05", "GET /c/?filter_a=1 HTTP/1.1", "200", "")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := convertBundle(t, dir, "r", twoSites(dir), testEnv()); err != nil {
		t.Fatal(err)
	}
	var reg identityRegistry
	if err := crawlreplay.DecodeStrictJSON(mustRead(t, filepath.Join(dir, "registry.json")), &reg); err != nil {
		t.Fatal(err)
	}
	sites, accounts := 0, 0
	for name := range reg.Names {
		switch {
		case strings.HasPrefix(name, "dom-"):
			sites++
		case strings.HasPrefix(name, "acct-"):
			accounts++
		default:
			t.Fatalf("registry holds %q; only site, account and episode pseudonyms belong there", name)
		}
	}
	if sites != 2 || accounts != 2 {
		t.Fatalf("registry holds %d sites and %d accounts, want 2 and 2", sites, accounts)
	}
}

func TestRegistryLockSurvivesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fingerprint := saltFingerprint(bytes.Repeat([]byte{0x42}, 32))
	first, err := openRegistry(osFS{}, path, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	names := map[string]string{"acct-000001": "000001" + strings.Repeat("a", 58)}
	if _, err = first.add(names); err != nil {
		t.Fatal(err)
	}
	if err = first.save(); err != nil {
		t.Fatal(err)
	}
	second, err := openRegistry(osFS{}, path, fingerprint)
	if err == nil {
		second.close()
		t.Fatal("registry replacement released the conversion lock")
	}
	if !errors.Is(err, errRegistry) {
		t.Fatalf("second conversion: %v", err)
	}
	first.close()
	third, err := openRegistry(osFS{}, path, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer third.close()
	if third.Names["acct-000001"] != names["acct-000001"] {
		t.Fatal("saved reservation lost after lock handoff")
	}
}

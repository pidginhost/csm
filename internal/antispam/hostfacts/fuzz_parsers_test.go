package hostfacts

import (
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/pidginhost/csm/internal/antispam"
)

func FuzzRedisEndpoint(f *testing.F) {
	for _, config := range []string{`{"servers":"/r.sock"}`, `{"servers":["192.0.2.1"]}`, `{"fuzzy":null}`, `null`, `{}`} {
		f.Add(config, fuzzyWorkerDump(""))
	}
	f.Add(`{"servers":"/r.sock"}`, `{"worker":[{"fuzzy":{}},{"fuzzy":{}}]}`)
	f.Fuzz(func(t *testing.T, config, full string) {
		endpoint, unix, password, err := redisEndpoint(antispam.LearningDumps{Redis: []byte(config)}, []byte(full))
		if err != nil {
			if endpoint != "" || unix || password.Reveal() != "" {
				t.Fatal("failed Redis selection returned usable backend settings")
			}
			return
		}
		if !json.Valid([]byte(config)) || !json.Valid([]byte(full)) || endpoint == "" || unix != strings.HasPrefix(endpoint, "/") {
			t.Fatal("Redis selection accepted malformed configuration")
		}
	})
}

func FuzzLearningUDP(f *testing.F) {
	f.Add(udpHeader)
	f.Add(udpHeader + "12: 0100007F:2C47 00000000:0000 07 0:0 0:0 0 979 0 1\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		trusted := func(uid int) bool { return uid == 0 || uid == 979 }
		found, foreign, err := parseFuzzyListening(data, trusted)
		if err != nil && (found || foreign) {
			t.Fatal("unreadable UDP table reported a listener")
		}
		if _, _, err := parseFuzzyListening(data+"\ntruncated\n", trusted); err == nil {
			t.Fatal("truncated UDP table accepted")
		}
	})
}

func FuzzLearningUDP6(f *testing.F) {
	f.Add(udp6Header)
	f.Add(udp6Header + "12: 0000000000000000FFFF00000100007F:2C47 00000000000000000000000000000000:0000 07 0:0 0:0 0 4321 0 1\n")
	f.Add(udp6Header + "12: 00000000000000000000000001000000:2C47 00000000000000000000000000000000:0000 07 0:0 0:0 0 979 0 1\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		trusted := func(uid int) bool { return uid == 0 || uid == 979 }
		foreign, err := parseUDP6Foreign(data, trusted)
		if err != nil && foreign {
			t.Fatal("unreadable UDP6 table reported a listener")
		}
		if _, err := parseUDP6Foreign(data+"\ntruncated\n", trusted); err == nil {
			t.Fatal("truncated UDP6 table accepted")
		}
	})
}

func FuzzRedisInfo(f *testing.F) {
	for _, data := range []string{"used_memory:0\r\n", "used_memory:\n", "used_memory:1\nused_memory:2\n", ""} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if value, ok := infoField(data, "used_memory"); ok && value == "" {
			t.Fatal("empty INFO value accepted")
		}
		if _, ok := infoField(data+"\nused_memory:1\nused_memory:2\n", "used_memory"); ok {
			t.Fatal("ambiguous INFO values accepted")
		}
	})
}

func FuzzParseStoredKeypair(f *testing.F) {
	data, err := json.Marshal(storedKeypair{Pubkey: base32Key(1), Privkey: base32Key(2)})
	if err != nil {
		f.Fatal(err)
	}
	for _, suffix := range []string{"", "\n", "}", "]", "{}", "null"} {
		f.Add(string(data) + suffix)
	}
	f.Add(`{"pubkey":"invalid","privkey":"invalid"}`)
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		kp, err := parseStoredKeypair(data)
		if err != nil {
			if kp.Public != "" || kp.Private.Reveal() != "" {
				t.Fatal("rejected keypair returned key material")
			}
			switch err.Error() {
			case "is not a keypair object", "public key is not a 52-character rspamd base32 key",
				"private key is not a 52-character rspamd base32 key":
			default:
				t.Fatal("keypair error contains unexpected text")
			}
			return
		}
		if !json.Valid([]byte(data)) || kp.Validate() != nil {
			t.Fatal("accepted malformed keypair")
		}
	})
}

func FuzzParseGroupMembers(f *testing.F) {
	f.Add("service:x:974:_rspamd,tenant\n", "primary:x:1001:974::/:/bin/false\n")
	f.Add("service:x:974:\n", "")
	f.Add("alias:x:974:_rspamd\nservice:x:974:tenant\n", "")
	f.Add("service:x:974:_rspamd\n", "truncated:x:1001\n")
	f.Add("service:x:974:tenant\x00\n", "")
	f.Fuzz(func(t *testing.T, groups, passwd string) {
		want := map[int]bool{974: true}
		got := parseGroupMembers(groups, passwd, want)
		for gid, members := range got {
			if gid != 974 {
				t.Fatal("unrequested group returned")
			}
			for _, member := range members {
				if member == "" || strings.ContainsAny(member, ":,\x00 \t\r\n\v\f") {
					t.Fatal("invalid account name returned")
				}
			}
		}
		if len(parseGroupMembers(groups+"\nmalformed", passwd, want)) != 0 ||
			len(parseGroupMembers(groups, passwd+"\nmalformed", want)) != 0 {
			t.Fatal("malformed account record left a trusted membership list")
		}
		withPrimary := parseGroupMembers(groups, passwd+"\nprobe:x:1001:974::/:/bin/false\n", want)
		if withPrimary != nil && !slices.Contains(withPrimary[974], "probe") {
			t.Fatal("complete account data lost a primary-group member")
		}
	})
}

func FuzzParseProbeReply(f *testing.F) {
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("probe.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure} {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: true, RCode: rcode}, Questions: []dnsmessage.Question{question}}
		packet, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(packet)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		reply := parseProbeReply(packet, 42, question)
		if (!reply.matched || reply.truncated || reply.answer.Failed || reply.answer.NXDomain) && len(reply.answer.Addrs) != 0 {
			t.Fatal("incomplete or unsuccessful reply returned listing addresses")
		}
		for _, value := range reply.answer.Addrs {
			addr, err := netip.ParseAddr(value)
			if err != nil || !addr.Is4() || addr.String() != value {
				t.Fatal("reply returned a noncanonical A record")
			}
		}
	})
}

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

func FuzzReadCanaryReply(f *testing.F) {
	for _, reply := range []string{
		"HTTP/1.1 200 OK\r\n\r\n" + `{"symbols":{"CSM_IP_CANARY":{"options":["gabcdef012345"]}}}`,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\n" + `{"symbols":{"CSM_IP_CANARY":{"options":["garbitrary reply text"]}}}`,
		"HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", maxCanaryBody+100) + "\r\n\r\n{}" + strings.Repeat(" ", maxCanaryBody),
		"HTTP/1.1 200 OK\r\nContent-Length: reply-marker\r\n\r\n",
		"", "reply-marker\r\n\r\n",
	} {
		f.Add(reply)
	}
	f.Fuzz(func(t *testing.T, reply string) {
		r := &countedReader{Reader: strings.NewReader(reply)}
		gen, err := readCanaryReply(io.NopCloser(r))
		if r.read > maxCanaryReply+1 {
			t.Fatalf("read %d bytes beyond the reply budget", r.read)
		}
		if err != nil {
			if gen != "" {
				t.Fatal("failed probe returned a generation")
			}
			switch message := err.Error(); message {
			case "rspamd /checkv2 returned an invalid HTTP response", "rspamd /checkv2 reply could not be read",
				"rspamd /checkv2 reply is too large", "rspamd /checkv2 reply is not JSON",
				"rspamd /checkv2 returned an invalid map generation":
			default:
				if !strings.HasPrefix(message, "rspamd /checkv2 returned HTTP ") || len(message) > 33 {
					t.Fatalf("unexpected error text: %q", message)
				}
			}
		} else if gen != "" && (len(gen) != 12 || strings.Trim(gen, "0123456789abcdef") != "") {
			t.Fatalf("reply returned an invalid generation: %q", gen)
		}
	})
}

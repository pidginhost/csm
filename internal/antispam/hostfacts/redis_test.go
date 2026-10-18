package hostfacts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// respServer answers the commands RedisProbe sends. config maps CONFIG GET
// names to values; fail names a command that answers with an error.
type respServer struct {
	config      map[string]string
	memory      string
	server      string
	password    string
	fail        string
	failReply   string
	delay       time.Duration
	mu          sync.Mutex
	commands    []string
	connections int
}

func (s *respServer) serve(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "redis.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections++
			s.mu.Unlock()
			go s.handle(conn)
		}
	}()
	return sock
}

func (s *respServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESP(r)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.Join(args, " "))
		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		s.mu.Unlock()
		switch {
		case s.fail != "" && strings.HasPrefix(cmd, s.fail):
			_, _ = io.WriteString(conn, "-ERR refused "+s.failReply+"\r\n")
		case strings.HasPrefix(cmd, "AUTH"):
			if args[len(args)-1] != s.password {
				_, _ = io.WriteString(conn, "-WRONGPASS invalid username-password pair\r\n")
				continue
			}
			_, _ = io.WriteString(conn, "+OK\r\n")
		case strings.HasPrefix(cmd, "CONFIG GET"):
			time.Sleep(s.delay)
			name := strings.ToLower(args[2])
			value, ok := s.config[name]
			if !ok {
				_, _ = io.WriteString(conn, "*0\r\n")
				continue
			}
			fmt.Fprintf(conn, "*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(name), name, len(value), value)
		case cmd == "INFO MEMORY":
			fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(s.memory), s.memory)
		case cmd == "INFO SERVER":
			fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(s.server), s.server)
		case cmd == "PING":
			_, _ = io.WriteString(conn, "+PONG\r\n")
		default:
			_, _ = io.WriteString(conn, "-ERR unknown command\r\n")
		}
	}
}

func readRESP(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("not an array: %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		head, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(head[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args[i] = string(buf[:size])
	}
	return args, nil
}

func healthyRedis() *respServer {
	return &respServer{
		config: map[string]string{
			"port": "0", "maxmemory": "4294967296", "maxmemory-policy": "noeviction",
			"appendonly": "yes", "save": "",
		},
		memory:   "# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\n",
		server:   "# Server\r\nredis_version:5.0.3\r\nredis_mode:standalone\r\n",
		password: "synthetic-redis-secret",
	}
}

func TestRedisProbeReadsLiveValues(t *testing.T) {
	srv := healthyRedis()
	sock := srv.serve(t)
	r := RedisProbe(context.Background(), sock, antispam.NewSecret(srv.password), os.Getuid())
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if r.Port != "0" || r.MaxMemory != 4294967296 || r.Policy != "noeviction" || r.AppendOnly != "yes" ||
		r.Save != "" || !r.SaveKnown || r.Used != 1048576 || r.Version != "5.0.3" || r.ServiceUID != os.Getuid() {
		t.Fatalf("facts = %+v", r)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	reads := map[string]int{}
	for _, c := range srv.commands {
		// The handshake and one PING that proves the verified connection.
		if strings.HasPrefix(c, "HELLO 2 ") || strings.HasPrefix(c, "AUTH ") || c == "PING" {
			continue
		}
		switch c {
		case "CONFIG GET PORT", "CONFIG GET MAXMEMORY", "CONFIG GET MAXMEMORY-POLICY", "CONFIG GET APPENDONLY", "CONFIG GET SAVE", "CONFIG GET TLS-PORT", "INFO MEMORY", "INFO SERVER":
			reads[c]++
		default:
			t.Error("probe sent an unexpected command")
		}
	}
	if len(reads) != 8 {
		t.Fatal("probe did not collect every live value")
	}
	for command, count := range reads {
		if count != 1 {
			t.Errorf("%s sent %d times", command, count)
		}
	}
}

func TestRedisProbeErrorKeepsNoPassword(t *testing.T) {
	const secret = "synthetic-redis-secret"
	for name, srv := range map[string]*respServer{
		"wrong password": func() *respServer { s := healthyRedis(); s.password = "other"; return s }(),
		"config refused": func() *respServer { s := healthyRedis(); s.fail = "CONFIG GET"; return s }(),
		"info refused":   func() *respServer { s := healthyRedis(); s.fail = "INFO"; return s }(),
		"bad memory":     func() *respServer { s := healthyRedis(); s.memory = "# Memory\r\n"; return s }(),
		"bad maxmemory":  func() *respServer { s := healthyRedis(); s.config["maxmemory"] = "lots"; return s }(),
	} {
		t.Run(name, func(t *testing.T) {
			r := RedisProbe(context.Background(), srv.serve(t), antispam.NewSecret(secret), os.Getuid())
			if r.Err == nil {
				t.Fatalf("facts = %+v, want an error", r)
			}
			if strings.Contains(fmt.Sprintf("%v %+v", r.Err, r), secret) {
				t.Fatal("probe result carries the password")
			}
		})
	}
	r := RedisProbe(context.Background(), filepath.Join(t.TempDir(), "absent.sock"), antispam.NewSecret(secret), os.Getuid())
	if r.Err == nil || strings.Contains(r.Err.Error(), secret) {
		t.Fatalf("absent socket: %v", r.Err)
	}
}

// A process that is not the expected Redis owner never receives the
// password, even if it answers at the configured path.
func TestRedisProbeRejectsWrongPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "redis.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	type received struct {
		connections int
		bytes       int64
		err         error
	}
	done := make(chan received, 1)
	go func() {
		var got received
		defer func() { done <- got }()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			got.connections++
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := io.Copy(io.Discard, conn)
			_ = conn.Close()
			got.bytes += n
			if err != nil {
				got.err = err
				return
			}
		}
	}()
	r := RedisProbe(context.Background(), sock, antispam.NewSecret(healthyRedis().password), os.Getuid()+1)
	_ = l.Close()
	got := <-done
	if r.Err == nil || r.ServiceUID != -1 {
		t.Fatalf("facts = %+v, want a peer error", r)
	}
	if got.err != nil || got.connections < 1 || got.bytes != 0 {
		t.Fatalf("unverified peer: connections=%d bytes=%d err=%v", got.connections, got.bytes, got.err)
	}
	if r := RedisProbe(context.Background(), "192.0.2.1:6379", antispam.NewSecret(healthyRedis().password), 0); r.Err == nil {
		t.Fatal("a TCP endpoint was probed")
	}
}

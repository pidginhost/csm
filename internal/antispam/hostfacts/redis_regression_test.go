package hostfacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"log"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pidginhost/csm/internal/antispam"
)

type redisTestLogger struct{ *log.Logger }

func (l redisTestLogger) Printf(_ context.Context, format string, args ...any) {
	l.Logger.Printf(format, args...)
}

func TestRedisProbeDoesNotLogAuthenticationReply(t *testing.T) {
	var output bytes.Buffer
	redis.SetLogger(redisTestLogger{log.New(&output, "", 0)})
	t.Cleanup(func() { redis.SetLogger(redisTestLogger{log.New(os.Stderr, "redis: ", log.LstdFlags)}) })
	srv := healthyRedis()
	srv.password = rand.Text()
	srv.fail = "AUTH"
	srv.failReply = srv.password
	r := RedisProbe(context.Background(), srv.serve(t), antispam.NewSecret(srv.password), os.Getuid())
	if r.Err == nil {
		t.Fatal("authentication failure accepted")
	}
	if strings.Contains(output.String(), srv.password) || strings.Contains(r.Err.Error(), srv.password) {
		t.Fatal("Redis authentication reply leaked the password")
	}
}

func TestRedisProbeHonorsDeadline(t *testing.T) {
	srv := healthyRedis()
	srv.delay = time.Second
	sock := srv.serve(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := RedisProbe(ctx, sock, antispam.NewSecret(srv.password), os.Getuid())
	if r.Err == nil || time.Since(start) >= 250*time.Millisecond {
		t.Fatal("Redis probe ignored the caller's deadline")
	}
}

func TestRedisProbeCollectsTLSListener(t *testing.T) {
	srv := healthyRedis()
	srv.config["tls-port"] = "6380"
	r := RedisProbe(context.Background(), srv.serve(t), antispam.NewSecret(srv.password), os.Getuid())
	if r.Err != nil || r.TLSPort != "6380" {
		t.Fatal("Redis TLS listener was not collected")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !slices.Contains(srv.commands, "CONFIG GET TLS-PORT") {
		t.Fatal("Redis TLS listener was not checked")
	}
}

func TestRedisProbeUsesOneConnection(t *testing.T) {
	srv := healthyRedis()
	r := RedisProbe(context.Background(), srv.serve(t), antispam.NewSecret(srv.password), os.Getuid())
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.connections != 1 {
		t.Fatal("Redis credentials and values were collected from separate connections")
	}
}

func TestRedisProbeRejectsUnreadableValues(t *testing.T) {
	for name, change := range map[string]func(*respServer){
		"empty version":     func(s *respServer) { s.server = "redis_version:\r\n" },
		"duplicate version": func(s *respServer) { s.server += "redis_version:7.0.0\r\n" },
		"duplicate memory":  func(s *respServer) { s.memory += "used_memory:0\r\n" },
		"bad port":          func(s *respServer) { s.config["port"] = "unknown" },
		"empty policy":      func(s *respServer) { s.config["maxmemory-policy"] = "" },
		"bad appendonly":    func(s *respServer) { s.config["appendonly"] = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			srv := healthyRedis()
			change(srv)
			r := RedisProbe(context.Background(), srv.serve(t), antispam.NewSecret(srv.password), os.Getuid())
			if r.Err == nil {
				t.Fatal("unreadable live value returned no error")
			}
		})
	}
}

// Package redisinfo wraps the go-redis client for the few read-only
// INFO calls CSM needs (memory metrics, keyspace counts). It replaces
// the `redis-cli info <section>` shell-outs the performance UI used
// to issue per-poll, eliminating libc/libpthread fork churn on hosts
// with a busy metrics dashboard.
//
// The client is a lazy package-level singleton: first call opens a
// connection-pooled client against the local redis socket / TCP, all
// subsequent calls reuse it. No Close path because the daemon runs
// for the host's lifetime; go-redis cleans up on process exit.
//
// Connection target matches redis-cli's default behaviour:
//
//	127.0.0.1:6379, no password, db 0
//
// When REDISCLI_AUTH is set, the client uses it as the password so
// daemon environments that previously made redis-cli work keep working.
// Hosts running redis on a non-default socket can override by calling
// SetAddr before the first MemoryUsage / Keyspace call. Absolute
// paths are treated as Unix sockets.
package redisinfo

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultAddr = "127.0.0.1:6379"

var (
	mu          sync.Mutex
	defaultDB   *redis.Client
	clientBuilt bool
	addr        = defaultAddr
	password    = ""
)

// SetAddr overrides the connection target before the singleton opens.
// Calls after the first MemoryUsage / Keyspace are ignored: the
// singleton has already been built. Tests can also use SetClientForTest
// to swap the singleton wholesale.
func SetAddr(a, pwd string) {
	mu.Lock()
	defer mu.Unlock()
	if clientBuilt {
		return
	}
	addr = a
	password = pwd
}

// SetClientForTest replaces the singleton with a caller-supplied
// client (typically pointed at miniredis or a real test instance).
// Pass nil to clear the override and let the next call rebuild the
// real singleton.
func SetClientForTest(c *redis.Client) {
	mu.Lock()
	defer mu.Unlock()
	defaultDB = c
	clientBuilt = c != nil
}

func client() *redis.Client {
	mu.Lock()
	defer mu.Unlock()
	if defaultDB == nil {
		defaultDB = redis.NewClient(redisOptions(addr, password))
		clientBuilt = true
	}
	return defaultDB
}

func redisOptions(target, pwd string) *redis.Options {
	network := "tcp"
	if strings.HasPrefix(target, "/") {
		network = "unix"
	}
	if pwd == "" {
		pwd = os.Getenv("REDISCLI_AUTH")
	}
	return &redis.Options{
		Network:  network,
		Addr:     target,
		Password: pwd,
		DB:       0,
		// Fail fast when redis is absent: this client only serves the
		// metrics dashboard, never a hot path. Default MaxRetries=3 +
		// ReadTimeout=3s would block the perfMetrics sampler for >9s on
		// a host without redis (a normal config -- CSM does not require
		// redis to run).
		DialTimeout:  500 * time.Millisecond,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
		MaxRetries:   -1, // disable retries entirely
		PoolTimeout:  500 * time.Millisecond,
		PoolSize:     2,
	}
}

// MemoryUsage returns the redis used_memory and maxmemory values
// from `INFO memory`, in bytes. Either may be zero if the server
// omits the field. err non-nil only on connection / protocol error.
func MemoryUsage(ctx context.Context) (used, max uint64, err error) {
	c := client()
	if c == nil {
		return 0, 0, fmt.Errorf("redisinfo: client not initialised")
	}
	raw, err := c.Info(ctx, "memory").Result()
	if err != nil {
		return 0, 0, err
	}
	used, max = parseMemoryInfo(raw)
	return used, max, nil
}

func parseMemoryInfo(raw string) (used, max uint64) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "used_memory:"):
			used, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "used_memory:")), 10, 64)
		case strings.HasPrefix(line, "maxmemory:"):
			max, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "maxmemory:")), 10, 64)
		}
	}
	return used, max
}

// Keyspace returns the sum of `keys=N` across every db<n> line in
// `INFO keyspace`. err non-nil only on connection / protocol error.
func Keyspace(ctx context.Context) (int64, error) {
	c := client()
	if c == nil {
		return 0, fmt.Errorf("redisinfo: client not initialised")
	}
	raw, err := c.Info(ctx, "keyspace").Result()
	if err != nil {
		return 0, err
	}
	return parseKeyspaceInfo(raw), nil
}

func parseKeyspaceInfo(raw string) int64 {
	var total int64
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "db") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		for _, kv := range strings.Split(parts[1], ",") {
			if strings.HasPrefix(kv, "keys=") {
				n, _ := strconv.ParseInt(strings.TrimPrefix(kv, "keys="), 10, 64)
				total += n
			}
		}
	}
	return total
}

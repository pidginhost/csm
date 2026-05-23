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
//
// Tests can intercept via SetMemoryUsageForTest.
func MemoryUsage(ctx context.Context) (used, max uint64, err error) {
	if fn := getMemoryUsageMock(); fn != nil {
		return fn(ctx)
	}
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

// MemoryUsageFunc is the signature SetMemoryUsageForTest accepts.
type MemoryUsageFunc func(ctx context.Context) (used, max uint64, err error)

// KeyspaceStatsFunc is the signature SetKeyspaceStatsForTest accepts.
type KeyspaceStatsFunc func(ctx context.Context) (KeyspaceStat, error)

// ConfigGetFunc is the signature SetConfigGetForTest accepts.
type ConfigGetFunc func(ctx context.Context, name string) (string, error)

var (
	mockMu     sync.RWMutex
	memMock    MemoryUsageFunc
	keyMock    KeyspaceStatsFunc
	configMock ConfigGetFunc
)

// SetMemoryUsageForTest installs an interceptor for MemoryUsage. Pass
// nil to clear. Production code paths must NOT call this.
func SetMemoryUsageForTest(fn MemoryUsageFunc) {
	mockMu.Lock()
	defer mockMu.Unlock()
	memMock = fn
}

// SetKeyspaceStatsForTest installs an interceptor for KeyspaceStats
// (and Keyspace, which proxies to it). Pass nil to clear.
func SetKeyspaceStatsForTest(fn KeyspaceStatsFunc) {
	mockMu.Lock()
	defer mockMu.Unlock()
	keyMock = fn
}

// SetConfigGetForTest installs an interceptor for ConfigGet. Pass nil
// to clear.
func SetConfigGetForTest(fn ConfigGetFunc) {
	mockMu.Lock()
	defer mockMu.Unlock()
	configMock = fn
}

func getMemoryUsageMock() MemoryUsageFunc {
	mockMu.RLock()
	defer mockMu.RUnlock()
	return memMock
}

func getKeyspaceStatsMock() KeyspaceStatsFunc {
	mockMu.RLock()
	defer mockMu.RUnlock()
	return keyMock
}

func getConfigGetMock() ConfigGetFunc {
	mockMu.RLock()
	defer mockMu.RUnlock()
	return configMock
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
	stats, err := KeyspaceStats(ctx)
	if err != nil {
		return 0, err
	}
	return stats.TotalKeys, nil
}

// KeyspaceStat is the aggregated breakdown of `INFO keyspace`. Keys
// counts all keys across all dbs; Expires counts the subset with a
// TTL applied.
type KeyspaceStat struct {
	TotalKeys    int64
	TotalExpires int64
}

// KeyspaceStats returns the per-db sums from `INFO keyspace`.
//
// Tests can intercept via SetKeyspaceStatsForTest.
func KeyspaceStats(ctx context.Context) (KeyspaceStat, error) {
	if fn := getKeyspaceStatsMock(); fn != nil {
		return fn(ctx)
	}
	c := client()
	if c == nil {
		return KeyspaceStat{}, fmt.Errorf("redisinfo: client not initialised")
	}
	raw, err := c.Info(ctx, "keyspace").Result()
	if err != nil {
		return KeyspaceStat{}, err
	}
	return parseKeyspaceStats(raw), nil
}

// ConfigGet returns the value of a single CONFIG GET parameter (e.g.
// "maxmemory", "save", "maxmemory-policy"). Empty result returns
// ("", nil) so callers can distinguish "unset" from "connection error".
//
// Tests can intercept via SetConfigGetForTest.
func ConfigGet(ctx context.Context, name string) (string, error) {
	if fn := getConfigGetMock(); fn != nil {
		return fn(ctx, name)
	}
	c := client()
	if c == nil {
		return "", fmt.Errorf("redisinfo: client not initialised")
	}
	m, err := c.ConfigGet(ctx, name).Result()
	if err != nil {
		return "", err
	}
	if v, ok := m[name]; ok {
		return v, nil
	}
	return "", nil
}

func parseKeyspaceInfo(raw string) int64 {
	return parseKeyspaceStats(raw).TotalKeys
}

func parseKeyspaceStats(raw string) KeyspaceStat {
	var stat KeyspaceStat
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
			kv = strings.TrimSpace(kv)
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				continue
			}
			val, perr := strconv.ParseInt(kv[eq+1:], 10, 64)
			if perr != nil {
				continue
			}
			switch kv[:eq] {
			case "keys":
				stat.TotalKeys += val
			case "expires":
				stat.TotalExpires += val
			}
		}
	}
	return stat
}

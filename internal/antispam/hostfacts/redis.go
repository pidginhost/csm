package hostfacts

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pidginhost/csm/internal/antispam"
)

const redisTimeout = 500 * time.Millisecond

// RedisProbe reads the live settings learning depends on from the Redis
// Unix socket at endpoint. The password is sent only on a connection whose
// peer is uid peer, the socket's verified owner: a process squatting the path
// gets nothing. It only reads: CONFIG GET and INFO. Errors are fixed text
// naming the step; the password never appears in them.
func RedisProbe(ctx context.Context, endpoint string, password antispam.Secret, peer int) antispam.RedisFacts {
	r := antispam.RedisFacts{Endpoint: endpoint, Unix: strings.HasPrefix(endpoint, "/"), ServiceUID: -1}
	if !r.Unix {
		r.Err = errors.New("redis: CSM probes only a Unix socket")
		return r
	}
	errPeer := errors.New("redis: the socket is not served by its owner")
	client := redis.NewClient(&redis.Options{
		Network: "unix", Addr: endpoint, Password: password.Reveal(),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: redisTimeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if peerUID(conn) != peer {
				_ = conn.Close()
				return nil, errPeer
			}
			return conn, nil
		},
		// RESP2 without CLIENT SETINFO: the probe must work on Redis 5 and
		// send nothing but reads.
		Protocol: 2, DisableIdentity: true,
		DialTimeout: redisTimeout, ReadTimeout: redisTimeout, WriteTimeout: redisTimeout,
		MaxRetries: -1, PoolSize: 1,
	})
	defer func() { _ = client.Close() }()
	if err := client.Ping(ctx).Err(); err != nil {
		r.Err = errors.New("redis: cannot connect to the socket as its owner")
		if errors.Is(err, errPeer) {
			r.Err = errPeer
		}
		return r
	}
	r.ServiceUID = peer
	values := map[string]string{}
	for _, name := range []string{"port", "maxmemory", "maxmemory-policy", "appendonly", "save"} {
		got, err := client.ConfigGet(ctx, name).Result()
		if err != nil {
			r.Err = errors.New("redis: CONFIG GET " + name + " failed")
			return r
		}
		value, ok := got[name]
		if !ok {
			r.Err = errors.New("redis: CONFIG GET " + name + " returned no value")
			return r
		}
		values[name] = value
	}
	r.Port, r.Policy, r.AppendOnly = values["port"], values["maxmemory-policy"], values["appendonly"]
	r.Save, r.SaveKnown = values["save"], true
	var err error
	if r.MaxMemory, err = strconv.ParseUint(values["maxmemory"], 10, 64); err != nil {
		r.Err = errors.New("redis: maxmemory is not a number")
		return r
	}
	memory, err := client.Info(ctx, "memory").Result()
	if err != nil {
		r.Err = errors.New("redis: INFO memory failed")
		return r
	}
	used, ok := infoField(memory, "used_memory")
	if r.Used, err = strconv.ParseUint(used, 10, 64); !ok || err != nil {
		r.Err = errors.New("redis: INFO memory has no used_memory")
		return r
	}
	server, err := client.Info(ctx, "server").Result()
	if err != nil {
		r.Err = errors.New("redis: INFO server failed")
		return r
	}
	if r.Version, ok = infoField(server, "redis_version"); !ok {
		r.Err = errors.New("redis: INFO server has no redis_version")
	}
	return r
}

func infoField(info, name string) (string, bool) {
	s := bufio.NewScanner(strings.NewReader(info))
	for s.Scan() {
		if key, value, ok := strings.Cut(strings.TrimSpace(s.Text()), ":"); ok && key == name {
			return value, true
		}
	}
	return "", false
}

// redisEndpoint finds the one Redis server the fuzzy worker uses: its own
// servers settings when it has any, else the global redis section. More
// than one server, or split read and write servers, is an error: CSM checks
// one backend.
func redisEndpoint(d antispam.LearningDumps, fullDump []byte) (endpoint string, unix bool, password antispam.Secret, err error) {
	var global map[string]json.RawMessage
	if json.Unmarshal(d.Redis, &global) != nil {
		return "", false, antispam.Secret{}, errors.New("rspamd's redis settings are not readable")
	}
	section := global
	if worker, ok := fuzzyWorker(fullDump); ok && hasServers(worker) {
		section = worker
	}
	var servers []string
	for _, key := range []string{"servers", "read_servers", "write_servers"} {
		raw, ok := section[key]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", false, antispam.Secret{}, errors.New("redis " + key + " is not a string")
		}
		for _, s := range strings.Split(value, ",") {
			if s = strings.TrimSpace(s); s != "" && !slices.Contains(servers, s) {
				servers = append(servers, s)
			}
		}
	}
	switch len(servers) {
	case 0:
		return "", false, antispam.Secret{}, errors.New("rspamd has no redis server for fuzzy storage")
	case 1:
	default:
		return "", false, antispam.Secret{}, errors.New("rspamd names more than one redis server for fuzzy storage")
	}
	if raw, ok := section["password"]; ok {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", false, antispam.Secret{}, errors.New("redis password is not a string")
		}
		password = antispam.NewSecret(value)
	}
	return servers[0], strings.HasPrefix(servers[0], "/"), password, nil
}

func hasServers(section map[string]json.RawMessage) bool {
	for _, key := range []string{"servers", "read_servers", "write_servers"} {
		if _, ok := section[key]; ok {
			return true
		}
	}
	return false
}

// fuzzyWorker returns the fuzzy worker's settings from the full dump, in
// either the list or the keyed form rspamd prints.
func fuzzyWorker(fullDump []byte) (map[string]json.RawMessage, bool) {
	var root map[string]json.RawMessage
	if json.Unmarshal(fullDump, &root) != nil {
		return nil, false
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(root["worker"], &entries) != nil {
		var keyed map[string]json.RawMessage
		if json.Unmarshal(root["worker"], &keyed) != nil {
			return nil, false
		}
		entries = []map[string]json.RawMessage{keyed}
	}
	for _, entry := range entries {
		if raw, ok := entry["fuzzy"]; ok {
			var w map[string]json.RawMessage
			if json.Unmarshal(raw, &w) == nil {
				return w, true
			}
		}
		var kind string
		if json.Unmarshal(entry["type"], &kind) == nil && kind == "fuzzy" {
			return entry, true
		}
	}
	return nil, false
}

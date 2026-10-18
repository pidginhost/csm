package hostfacts

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
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
				return nil, errors.New("redis connection failed")
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
		MaxRetries: -1, PoolSize: 1, DialerRetries: 1, ContextTimeoutEnabled: true,
	})
	defer func() { _ = client.Close() }()
	probe := client.Conn()
	defer func() { _ = probe.Close() }()
	// One connection supplies the peer check and every value, so a replaced
	// socket cannot answer part of the probe.
	if err := probe.Ping(ctx).Err(); err != nil {
		r.Err = errors.New("redis: cannot connect to the socket as its owner")
		if errors.Is(err, errPeer) {
			r.Err = errPeer
		}
		return r
	}
	r.ServiceUID = peer
	values := map[string]string{}
	for _, name := range []string{"port", "maxmemory", "maxmemory-policy", "appendonly", "save"} {
		got, err := probe.ConfigGet(ctx, name).Result()
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
	tls, err := probe.ConfigGet(ctx, "tls-port").Result()
	if err != nil {
		r.Err = errors.New("redis: CONFIG GET tls-port failed")
		return r
	}
	if value, ok := tls["tls-port"]; ok {
		if _, err = strconv.ParseUint(value, 10, 16); err != nil {
			r.Err = errors.New("redis: tls-port is not a port number")
			return r
		}
		r.TLSPort = value
	}
	r.Port, r.Policy, r.AppendOnly = values["port"], values["maxmemory-policy"], values["appendonly"]
	r.Save, r.SaveKnown = values["save"], true
	if _, err = strconv.ParseUint(r.Port, 10, 16); err != nil {
		r.Err = errors.New("redis: port is not a port number")
		return r
	}
	if strings.TrimSpace(r.Policy) == "" || (r.AppendOnly != "yes" && r.AppendOnly != "no") {
		r.Err = errors.New("redis: memory policy or persistence setting is not readable")
		return r
	}
	if r.MaxMemory, err = strconv.ParseUint(values["maxmemory"], 10, 64); err != nil {
		r.Err = errors.New("redis: maxmemory is not a number")
		return r
	}
	memory, err := probe.Info(ctx, "memory").Result()
	if err != nil {
		r.Err = errors.New("redis: INFO memory failed")
		return r
	}
	used, ok := infoField(memory, "used_memory")
	if r.Used, err = strconv.ParseUint(used, 10, 64); !ok || err != nil {
		r.Err = errors.New("redis: INFO memory has no used_memory")
		return r
	}
	server, err := probe.Info(ctx, "server").Result()
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
	var found string
	seen := false
	for s.Scan() {
		if key, value, ok := strings.Cut(strings.TrimSpace(s.Text()), ":"); ok && key == name {
			if seen || value == "" {
				return "", false
			}
			found, seen = value, true
		}
	}
	return found, seen && s.Err() == nil
}

// redisEndpoint follows the fuzzy backend's worker, redis.fuzzy (or
// fuzzy_storage), then global selection. Unsupported or ambiguous settings
// must stop collection before a different Redis instance can be probed.
func redisEndpoint(d antispam.LearningDumps, fullDump []byte) (endpoint string, unix bool, password antispam.Secret, err error) {
	global, err := antispam.ParseRspamdDumpObject(d.Redis)
	if err != nil {
		return "", false, antispam.Secret{}, errors.New("rspamd's redis settings are not readable")
	}
	worker, err := fuzzyWorker(fullDump)
	if err != nil {
		return "", false, antispam.Secret{}, err
	}
	section := worker
	if !hasServers(section) {
		section = global
		for _, name := range []string{"fuzzy", "fuzzy_storage"} {
			if raw, ok := global[name]; ok {
				specific, parseErr := antispam.ParseRspamdDumpObject(raw)
				if parseErr != nil {
					return "", false, antispam.Secret{}, errors.New("fuzzy Redis settings are not readable")
				}
				section = specific
				break
			}
		}
	}
	// Rspamd inherits authentication and other options from global Redis
	// settings even when the worker selects its own servers.
	option := func(name string) json.RawMessage {
		if raw, ok := section[name]; ok {
			return raw
		}
		return global[name]
	}
	if raw := option("sentinels"); raw != nil {
		return "", false, antispam.Secret{}, errors.New("redis sentinel backend cannot be identified from config alone")
	}
	if raw := option("ssl"); raw != nil && string(raw) != "false" {
		return "", false, antispam.Secret{}, errors.New("redis TLS backend cannot be probed")
	}
	if raw := option("username"); raw != nil {
		var username string
		if string(raw) == "null" || json.Unmarshal(raw, &username) != nil || (username != "" && username != "default") {
			return "", false, antispam.Secret{}, errors.New("redis named-user authentication cannot be probed")
		}
	}
	var servers []string
	readKey := ""
	for _, key := range []string{"read_servers", "servers", "server"} {
		if _, ok := section[key]; ok {
			readKey = key
			break
		}
	}
	for _, key := range []string{readKey, "write_servers"} {
		raw, ok := section[key]
		if !ok {
			continue
		}
		list, err := redisServers(raw)
		if err != nil {
			return "", false, antispam.Secret{}, err
		}
		for _, server := range list {
			if !slices.Contains(servers, server) {
				servers = append(servers, server)
			}
		}
	}
	if readKey == "" || len(servers) == 0 {
		return "", false, antispam.Secret{}, errors.New("rspamd has no redis server for fuzzy storage")
	}
	if len(servers) != 1 {
		return "", false, antispam.Secret{}, errors.New("rspamd names more than one redis server for fuzzy storage")
	}
	if raw := option("password"); raw != nil {
		var value string
		if string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
			return "", false, antispam.Secret{}, errors.New("redis password is not a string")
		}
		password = antispam.NewSecret(value)
	}
	return servers[0], strings.HasPrefix(servers[0], "/"), password, nil
}

func redisServers(raw json.RawMessage) ([]string, error) {
	var values []string
	var single string
	if string(raw) == "null" {
		return nil, errors.New("redis servers are not readable")
	}
	if json.Unmarshal(raw, &single) == nil {
		values = []string{single}
	} else if json.Unmarshal(raw, &values) != nil {
		return nil, errors.New("redis servers are not readable")
	}
	var servers []string
	for _, value := range values {
		for _, rawServer := range strings.Split(value, ",") {
			server, err := redisAddress(strings.TrimSpace(rawServer))
			if err != nil {
				return nil, err
			}
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("redis servers are empty")
	}
	return servers, nil
}

func redisAddress(server string) (string, error) {
	bad := errors.New("redis server address is not supported")
	if server == "" || strings.ContainsAny(server, "@ \t\r\n\x00") {
		return "", bad
	}
	if strings.HasPrefix(server, "/") {
		return server, nil
	}
	if addr, err := netip.ParseAddr(server); err == nil {
		return net.JoinHostPort(addr.String(), "6379"), nil
	}
	if !strings.ContainsAny(server, ":/[]") {
		return net.JoinHostPort(server, "6379"), nil
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil || host == "" || strings.ContainsAny(host, "/[]") {
		return "", bad
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || port == "0" {
		return "", bad
	}
	return net.JoinHostPort(host, port), nil
}

func hasServers(section map[string]json.RawMessage) bool {
	for _, key := range []string{"servers", "server", "read_servers", "write_servers"} {
		if _, ok := section[key]; ok {
			return true
		}
	}
	return false
}

func workerEntries(raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	bad := errors.New("rspamd's worker settings are not readable")
	var objects []json.RawMessage
	if json.Unmarshal(raw, &objects) != nil {
		objects = []json.RawMessage{raw}
	}
	if objects == nil {
		return nil, bad
	}
	entries := make([]map[string]json.RawMessage, 0, len(objects))
	for _, object := range objects {
		entry, err := antispam.ParseRspamdDumpObject(object)
		if err != nil {
			return nil, bad
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// An absent fuzzy worker is legitimate before installation; malformed or
// repeated workers must never silently select the global Redis instead.
func fuzzyWorker(fullDump []byte) (map[string]json.RawMessage, error) {
	root, err := antispam.ParseRspamdDumpObject(fullDump)
	if err != nil {
		return nil, errors.New("rspamd's worker settings are not readable")
	}
	entries, err := workerEntries(root["worker"])
	if err != nil {
		return nil, err
	}
	var found map[string]json.RawMessage
	for _, entry := range entries {
		var worker map[string]json.RawMessage
		if raw, ok := entry["type"]; ok {
			var kind string
			if json.Unmarshal(raw, &kind) != nil || kind == "" || strings.ContainsRune(kind, '\x00') {
				return nil, errors.New("rspamd's worker type is not readable")
			}
			if kind == "fuzzy" {
				worker = entry
			}
		} else if raw, ok := entry["fuzzy"]; ok {
			worker, err = antispam.ParseRspamdDumpObject(raw)
			if err != nil {
				return nil, errors.New("rspamd's fuzzy worker is not readable")
			}
		}
		if worker != nil {
			if found != nil {
				return nil, errors.New("rspamd names more than one fuzzy worker")
			}
			found = worker
		}
	}
	return found, nil
}

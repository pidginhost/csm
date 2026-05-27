# Upstream Threat-Intel HTTP Contract (v1)

This document specifies the HTTP API CSM expects when
`reputation.upstream.enabled: true`. A panel host (or any HTTP server)
can implement it; phpanel's reference implementation lives in
`phpanel-server-agent`.

## Endpoint

```
GET <reputation.upstream.url>/lookup?ip=<ip>
```

`reputation.upstream.url` must be an `https://` URL with a host. Plain
`http://` is accepted only for loopback hosts such as `127.0.0.1`,
`[::1]`, or `localhost`. CSM appends `/lookup` to that base URL.

## Authentication

CSM sends `Authorization: Bearer <token>` when
`reputation.upstream.token` (or its env var) is set. The server SHOULD
reject requests with a missing/invalid token via HTTP 401.

The token is resolved at every Score call: if `reputation.upstream.token_env`
is set and the env var is non-empty, it wins over the static `token` field.
This lets operators rotate the token via env without restarting the daemon.

## Request

- `ip` query parameter: IPv4 dotted-quad (e.g. `1.2.3.4`) or IPv6 in
  any RFC 5952 form. The server SHOULD normalize before lookup.

## Response

### 200 OK

```json
{
  "ip": "1.2.3.4",
  "score": 75,
  "source": "upstream",
  "ttl_sec": 900
}
```

- `ip` (required): echoes the input.
- `score` (required): integer 0..100. Higher means worse. `0` is "no
  signal" and the aggregator excludes it from averaging.
- `source` (optional): free-form identifier the server may set for
  audit-log surfacing.
- `ttl_sec` (optional): number of seconds CSM should cache this answer.
  Overrides `reputation.upstream.cache_ttl_min`. The server SHOULD
  return the smaller of its own cache lifetime and a sane default.

### 401 / 403

CSM treats as "no signal" - does not retry, does not cache. Logged as a
warning so operators see auth misconfigurations.

### 4xx / 5xx other

Treated as "no signal." The aggregator continues with whatever scores
the other sources returned.

CSM rejects malformed `200` responses, including an `ip` field that
does not match the requested IP or a `score` outside `0..100`.

## Caching

CSM caches each (ip, score) pair locally for `cache_ttl_min` minutes
(default 15) or for `ttl_sec` if the response provides it. A cache hit
does not contact the upstream. Bursts of detection events that touch
the same IP within the TTL window produce a single upstream call.

The local cache is capped at 10,000 IPs. When the cap is reached, CSM
prunes expired entries first and then removes the entry with the nearest
expiry time until the cache is back under the cap.

After repeated upstream failures, CSM opens a short circuit breaker and
temporarily treats the source as "no signal." When the cooldown expires,
only one probe request is allowed through; concurrent callers keep using
the fail-open path until that probe succeeds or fails.

## Sample server stub (Go)

```go
http.HandleFunc("/api/csm/ti/lookup", func(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("Authorization") != "Bearer "+os.Getenv("PHPANEL_CSM_TOKEN") {
        http.Error(w, "unauthorized", 401); return
    }
    ip := r.URL.Query().Get("ip")
    score := lookupCachedScoreFromAbuseIPDBOrRedis(ip) // your impl
    json.NewEncoder(w).Encode(map[string]interface{}{
        "ip": ip, "score": score, "source": "phpanel-cache", "ttl_sec": 900,
    })
})
```

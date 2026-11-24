# Upstream Threat-Intel HTTP Contract (v1)

This document specifies the HTTP API CSM expects when `reputation.upstream.enabled: true`. A panel host, or any HTTP server, can implement it. phpanel's reference implementation lives in `phpanel-server-agent`.

## Endpoint

```
GET <reputation.upstream.url>/lookup?ip=<ip>
```

`reputation.upstream.url` must be an `https://` URL with a host. Plain `http://` is accepted only for loopback hosts such as `127.0.0.1`, `[::1]`, or `localhost`. CSM appends `/lookup` to that base URL.

## Authentication

CSM sends `Authorization: Bearer <token>` when `reputation.upstream.token` (or its env var) is set. The server SHOULD reject requests with a missing or invalid token with HTTP 401.

Before each HTTP request, CSM reads `reputation.upstream.token_env` from its process environment. A non-empty value overrides the static `token` field.

Restart the daemon after editing its environment file. An export in another shell applies only to processes that inherit that shell's environment. A configuration reload does not replace the process environment. See [credential rotation](credential-rotation.md).

## Request

The `ip` query parameter is an IPv4 dotted-quad (e.g. `192.0.2.1`) or an IPv6 address in any RFC 5952 form. The server SHOULD normalize before lookup.

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

| Field | Required | Value |
|---|---|---|
| `ip` | Yes | Echoes the input. |
| `score` | Yes | Integer 0..100. Higher means worse. `0` is "no signal" and the aggregator excludes it from averaging. |
| `source` | No | Optional provider label. CSM does not use it to score or cache the address. |
| `ttl_sec` | No | A positive value can shorten the configured cache lifetime. CSM never extends `reputation.upstream.cache_ttl_min` on the server's advice. |

The server SHOULD return in `ttl_sec` the smaller of its own cache lifetime and a sane default.

CSM rejects malformed `200` responses. That includes an `ip` field that does not match the requested IP and a `score` outside `0..100`.

### 401 / 403

CSM treats the answer as "no signal". It does not retry and does not cache. It logs a warning so operators see auth misconfigurations.

### 4xx / 5xx other

CSM treats the answer as "no signal". The aggregator continues with whatever scores the other sources returned.

## Caching

CSM caches each (ip, score) pair locally for `cache_ttl_min` minutes (default 15), or for `ttl_sec` if the response provides it. A cache hit does not contact the upstream. Bursts of detection events that touch the same IP within the TTL window produce a single upstream call.

The local cache is capped at 10,000 IPs. When the cap is reached, CSM prunes expired entries first. It then removes the entry with the nearest expiry time until the cache is back under the cap.

## Repeated upstream failures

After repeated upstream failures, CSM opens a short circuit breaker and temporarily treats the source as "no signal".

When the cooldown expires, CSM lets only one probe request through. Concurrent callers keep getting "no signal" until that probe succeeds or fails.

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

# Abuse Report Contract (v1)

When `reputation.report.enabled: true`, CSM sends a minimized report for
each confirmed-abuse finding to every configured target. This page defines
the request a collector receives and the answers CSM understands. Use it to
build a private collector. The central abuse database implements the same
contract and accepts `ed25519` targets only. Node setup is in
[Threat Intelligence](threat-intel.md#abuse-reporting).

## What CSM reports

CSM reports a finding only when all of these hold:

- Its check maps to a class listed in `reputation.report.classes`. The
  mapping is in [Threat Intelligence](threat-intel.md#reported-findings).
- It is Critical, or High or above for `bad_asn_egress`.
- It names a source address that parses as an IP address.
- That address is public and not protected. CSM never reports private,
  loopback, link-local, multicast, carrier-grade NAT, documentation,
  benchmarking, reserved or other special-purpose addresses, `infra_ips`
  entries, Cloudflare edges, or verified crawlers. For NAT64 and 6to4
  sources, the same rules also apply to the embedded IPv4 address.

## Request

```
POST <target url>
Content-Type: application/json
X-CSM-Node: <node_id>
X-CSM-Key: <key_id>
X-CSM-Timestamp: <unix seconds, UTC>
X-CSM-Nonce: <32 lowercase hex characters>
X-CSM-Signature: ed25519=<hex> | sha256=<hex>
Authorization: Bearer <token>          (hmac targets whose token_env variable is set)
```

CSM posts to the configured URL as written and appends no path. Remote URLs
must use HTTPS; plain HTTP is accepted only for loopback hosts. CSM does not
follow redirects: a 3xx answer is a failed delivery and is retried. Each
request times out after 15 seconds.

## Body

```json
{"ip":"203.0.113.10","class":"bruteforce","count":1,"first_seen":"2023-11-14T22:13:20Z","last_seen":"2023-11-14T22:13:20Z"}
```

- `ip`: the source address in canonical text form. IPv6 is compressed and
  lowercase. An IPv4-mapped IPv6 address is sent as dotted IPv4.
- `class`: `bruteforce`, `php_relay`, `credential_stuffing` or
  `bad_asn_egress`.
- `count`: observations in this report. Version 1 always sends 1.
- `first_seen`, `last_seen`: RFC 3339 UTC time of the finding, which may
  carry fractional seconds. Version 1 sends the same value in both.

The body carries no hostnames, account names, domains, mailboxes, paths or
process data. The signature covers the SHA-256 of the body, so verify
against the raw bytes received, not a re-encoded copy.

## Signature

CSM signs a message built from six fields followed by the timestamp. Each
field is written as a 4-byte big-endian length, then its bytes:

| Order | Field | Value |
|---|---|---|
| 1 | Node | `X-CSM-Node` value |
| 2 | Key | `X-CSM-Key` value |
| 3 | Method | `POST` |
| 4 | Path | Decoded path of the configured URL, or `/` when it has none. The query string is not included. |
| 5 | Body hash | SHA-256 of the raw body, 32 raw bytes |
| 6 | Nonce | `X-CSM-Nonce` value |

The `X-CSM-Timestamp` value follows as an 8-byte big-endian signed integer.

The path is the one in CSM's configuration. A collector behind a proxy that
rewrites the path must verify against the original path.

The transport selects the algorithm:

- `ed25519`: an Ed25519 signature (RFC 8032, not prehashed) with the node's
  private key, sent as `X-CSM-Signature: ed25519=<128 hex characters>`. The
  collector verifies it with the public key it registered for that node and
  key ID.
- `hmac`: HMAC-SHA256 keyed with the `key_env` value exactly as set, not
  hex-decoded, sent as `X-CSM-Signature: sha256=<64 hex characters>`.

This differs from the per-finding webhook, whose HMAC covers only the body.

## Collector checks

A collector must:

1. Find the key for `X-CSM-Node` and `X-CSM-Key`.
2. Rebuild the signed message from the raw body and headers, then verify the
   signature. Compare HMAC values in constant time.
3. Reject a timestamp outside a window you choose, for example five minutes
   either side of your clock.
4. Remember each node and nonce pair for that window and reject a repeat.

Answer these failures with 401 or 403, never 422. CSM keeps the report
queued and retries it, so a node that is not yet approved or has a wrong
clock loses no reports once the problem is fixed.

## Test vector

Inputs:

- `X-CSM-Node: node-1`
- `X-CSM-Key: key-1`
- Target URL `https://abuse.example.net/report`, so the path is `/report`
- The body shown in [Body](#body), without a trailing newline
- `X-CSM-Nonce: 0123456789abcdef0123456789abcdef`
- `X-CSM-Timestamp: 1700000000`
- HMAC secret `example-secret`

Body SHA-256:

```
56f3e2c77c1456d41f210109cd069f5795c66ea3d825af3ac5f1d0bc1a008d2c
```

Signed message, hex:

```
000000066e6f64652d31000000056b65792d3100000004504f5354000000072f7265706f7274
0000002056f3e2c77c1456d41f210109cd069f5795c66ea3d825af3ac5f1d0bc1a008d2c
000000203031323334353637383961626364656630313233343536373839616263646566
000000006553f100
```

Header:

```
X-CSM-Signature: sha256=ae5e149cc7789d78c65b30d8d52a372a6d3bb999a84355d88d42f9c1874666e8
```

An `ed25519` target signs the same message bytes.

## Responses

CSM ignores the response body.

| Answer | What CSM does |
|---|---|
| 2xx | Delivered. The report leaves the queue. |
| 409 | Treated as delivered. Use it only for a report already stored. |
| 422 | Dropped and counted as lost, never resent. Use it only for a body you will never accept. |
| 429 | Retried after `Retry-After`, in seconds or as an HTTP date, up to one hour. Without it, retried after one minute. |
| Any other status, timeout or network error | Retried after one minute. |

[Threat Intelligence](threat-intel.md#abuse-reporting) describes how waits
grow while a collector keeps throttling.

## Delivery

- CSM keeps reports in an on-disk queue that survives restarts and sends
  each target its reports in queue order. When a target fails, its later
  reports wait for the next pass while other targets keep receiving theirs.
- When the queue is full (`reputation.report.spool_max`), CSM drops the
  oldest queued reports.
- A retry sends the same body with a new nonce, timestamp and signature, so
  the same report can arrive more than once, for example when an answer is
  lost. Deduplicate on node and body hash, and answer 409
  for a body already stored.

## Sample collector (Go)

An HMAC collector for the request above. `secretFor` returns the shared
secret for a node and key ID, or nil when unknown.

```go
// signedMessage rebuilds the bytes CSM signed for this request.
func signedMessage(r *http.Request, body []byte) ([]byte, error) {
	ts, err := strconv.ParseInt(r.Header.Get("X-CSM-Timestamp"), 10, 64)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	var msg []byte
	for _, f := range [][]byte{
		[]byte(r.Header.Get("X-CSM-Node")),
		[]byte(r.Header.Get("X-CSM-Key")),
		[]byte(r.Method),
		[]byte(r.URL.Path), // the path CSM was configured with
		sum[:],
		[]byte(r.Header.Get("X-CSM-Nonce")),
	} {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(f)))
		msg = append(msg, f...)
	}
	return binary.BigEndian.AppendUint64(msg, uint64(ts)), nil
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	secret := secretFor(r.Header.Get("X-CSM-Node"), r.Header.Get("X-CSM-Key"))
	msg, err := signedMessage(r, body)
	scheme, sigHex, _ := strings.Cut(r.Header.Get("X-CSM-Signature"), "=")
	sig, hexErr := hex.DecodeString(sigHex)
	if secret == nil || err != nil || hexErr != nil || scheme != "sha256" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Check the timestamp window and the nonce here, then decode and
	// store the report. Answer 409 for a body this node already sent.
	w.WriteHeader(http.StatusNoContent)
}
```

For an `ed25519` target, check for the `ed25519` scheme and replace the HMAC
step with `ed25519.Verify(publicKey, msg, sig)`.

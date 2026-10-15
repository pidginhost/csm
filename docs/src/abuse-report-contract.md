# Abuse Report Contract (v1)

When `reputation.report.enabled: true`, CSM queues minimized reports for
eligible confirmed-abuse findings, with one copy per usable target. This page defines
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
- Its finding timestamp is not zero.
- That address passes CSM's protection checks. CSM excludes private,
  loopback, link-local, multicast, carrier-grade NAT, documentation,
  benchmarking and selected special-purpose ranges, literal IPs and
  CIDRs in `infra_ips` and `firewall.infra_ips`, Cloudflare edges, and
  built-in or operator-configured crawler IP ranges. This check does not
  resolve infrastructure hostnames or consult rDNS crawler results.
  Teredo clients are not excluded solely for using Teredo. For NAT64 and
  6to4 sources, the same checks also apply to the embedded IPv4 address.

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
  private key. `key_env` must hold the 64-byte private key encoded as 128
  hex characters, not a 32-byte seed. The signature is sent as
  `X-CSM-Signature: ed25519=<128 hex characters>`. The collector verifies it
  with the public key it registered for that node and key ID.
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

Answer these failures with 401 or 403, never 422. CSM keeps retrying queued
reports so approval or clock repair can restore delivery. Queue overflow
can still discard reports during the outage; see [Delivery](#delivery).

## Test vector

This is a signature test using a documentation address. CSM's reporting
gate excludes that address from real reports.

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
| 429 | Retried after a positive `Retry-After`, in seconds or as an HTTP date, capped at one hour. A missing, invalid, zero or past value uses one minute. Repeated throttling can increase short waits as described below. |
| Any other status, timeout or network error | Retried after one minute. |

[Threat Intelligence](threat-intel.md#abuse-reporting) describes how waits
grow while a collector keeps throttling.

## Delivery

- Reports first enter a bounded memory queue before being written to disk.
  Memory overflow, failed persistence or a crash before persistence can
  lose reports. Normal shutdown drains accepted memory work to disk.
- Persisted reports survive restarts and are sent to each target in queue
  order. When a target fails, its later reports wait for the next pass
  while other targets can continue receiving theirs.
- `reputation.report.spool_max` is one shared capacity across all targets.
  Each report uses one entry per target. When full, CSM drops the oldest
  entries across the whole queue, including entries for other targets.
- Target names identify queued destinations. Use unique, stable names:
  the last usable target with a duplicate name wins. Removing or renaming
  a target discards its queued entries on the next delivery pass.
- A retry sends the same body with a new nonce, timestamp and signature, so
  the same report can arrive more than once, for example when an answer is
  lost. Deduplicate on node and body hash, and answer 409
  for a body already stored.

## Sample collector (Go)

This HMAC signature-verification skeleton is not a complete collector.
`secretFor` returns the shared secret for a node and key ID, or nil when
unknown. Before using it, implement the timestamp and replay checks above,
body validation, duplicate detection and durable storage at the marked
point. Return 2xx only after storing the report. If configured, also verify
the bearer token. The body limit rejects oversized requests rather than
verifying a truncated prefix.

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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
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

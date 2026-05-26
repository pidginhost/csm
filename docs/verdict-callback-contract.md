# Verdict Callback HTTP Contract (v1)

When `auto_response.verdict_callback.enabled: true`, CSM POSTs each
auto-block decision to the configured URL and reads an advisory
response. The endpoint is **not** a per-tenant nftables enforcement
plane - it lets phpanel observe and label decisions, downgrade them to
audit-only, and attach tenant attribution.

CSM runs its local block validation before calling the endpoint.
Malformed IPs, disabled IPv6 targets, infra IPs, and configured block
limits are rejected locally and are not sent to the callback.

## Endpoint

```
POST <auto_response.verdict_callback.url>
Content-Type: application/json
Accept: application/json
X-CSM-Signature: sha256=<hex>          (HMAC-SHA256 over raw body, omitted if no secret configured)
```

`auto_response.verdict_callback.url` must be an `http://` or `https://`
URL with a host. CSM POSTs directly to that URL (no path appended).

## Authentication

CSM signs the raw request body with HMAC-SHA256 using the configured
secret and sends the digest in `X-CSM-Signature: sha256=<hex>`. The
secret is resolved once per request/response exchange: if
`hmac_secret_env` is set and the env var is non-empty, it wins over the
static `hmac_secret` field. This lets operators rotate the secret via
env without restarting the daemon while keeping request and response
verification on the same key for that exchange.

The server MUST verify the signature with constant-time compare and
reject unsigned or invalid requests with 401.

### Response signing (required by default)

The server MUST sign its response body with the same HMAC-SHA256 scheme
(same secret, same `X-CSM-Signature: sha256=<hex>` header). CSM verifies
the response signature with constant-time compare before parsing the
verdict; an unsigned or forged response is rejected and CSM falls back
to its default block. Without this check an on-path attacker could
downgrade every "block" decision to "allow".

If the server cannot sign responses yet (e.g. mid-rollout), operators
can set `auto_response.verdict_callback.require_response_signature:
false` in `csm.yaml` to temporarily accept unsigned responses. The
default is `true` and there is no other way to disable the check.

## Request body

```json
{
  "ip": "1.2.3.4",
  "reason": "mail_bruteforce",
  "severity": "auto",
  "source": "auto_response"
}
```

- `ip` (required): the IP CSM is about to block.
- `reason` (required): short reason string (`mail_bruteforce`, `wp_login_bruteforce`, etc.).
- `severity` (optional): `"auto"` for auto-response decisions; reserved for future use.
- `source` (optional): `"auto_response"` (the only current emitter).

## Response body (200 OK)

```json
{
  "verdict": "block",
  "tenant_id": "tenant-42",
  "note": "matched dovecot user pattern"
}
```

- `verdict`: `"block"` (default; also returned if field omitted) or `"allow"` to override. **Any other string is rejected by CSM as a protocol error**, treated as "no decision" (CSM proceeds with the default block per fail-open semantics).
- `tenant_id` (optional): attribution string; CSM logs it alongside the decision.
- `note` (optional): free-form note logged for the verdict.

## Failure semantics

- Network error / timeout / non-200 HTTP response: CSM logs a warning and **proceeds with the default block**. The hook is fail-open at the transport level.
- 200 OK with `verdict: "allow"`: CSM does **not** modify nftables; logs the override to stderr.
- 200 OK with `verdict: "block"` or omitted: standard block path runs (which still honors `auto_response.dry_run` if set).
- 200 OK with unknown `verdict` string: rejected; treated as fail-open (default block).
- 200 OK with missing or invalid `X-CSM-Signature` (and `require_response_signature` not turned off): rejected as forged; treated as fail-open (default block). Operators see the rejection in stderr; recurring rejections indicate either a panel-side rollout gap or an active on-path attack.

## Limits

- CSM caps response body at 64 KB. Larger responses are rejected.
- Default request timeout is 2 seconds (configurable via `timeout_sec`, range 1-30).

## Sample server stub (Go)

```go
http.HandleFunc("/api/csm/verdict", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    if !verifySignature(r.Header.Get("X-CSM-Signature"), body, secret) {
        http.Error(w, "bad signature", 401); return
    }
    var req struct{ IP, Reason, Severity, Source string }
    _ = json.Unmarshal(body, &req)

    tenant := lookupTenantOwning(req.IP) // your impl
    verdict := "block"
    if isPanelInfra(req.IP) {            // never block our own infra
        verdict = "allow"
    }
    respBody, _ := json.Marshal(map[string]string{
        "verdict": verdict, "tenant_id": tenant,
    })
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(respBody)
    w.Header().Set("X-CSM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
    _, _ = w.Write(respBody)
})
```

## When to graduate this to per-tenant enforcement

This v1 hook surfaces tenant attribution but does not synthesize
per-tenant nftables rules. If/when phpanel wants real per-tenant
enforcement (block IP X from tenant Y's mailboxes only, allow elsewhere),
that's a separate plan that will need:
- Multi-set nftables rule generation per tenant
- A way to map an IP+tenant pair to an nftables verdict
- Lock-step config sync between CSM and the panel's tenant table

Do that work then, against a real call site, not on spec.

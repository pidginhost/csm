# Verdict Callback HTTP Contract (v1)

When `auto_response.verdict_callback.enabled: true`, CSM POSTs each
auto-block decision to the configured URL and reads an advisory
response. The endpoint is **not** a per-tenant nftables enforcement
plane - it lets phpanel observe and label decisions, downgrade them to
audit-only, and attach tenant attribution.

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
secret is resolved at every request: if `hmac_secret_env` is set and
the env var is non-empty, it wins over the static `hmac_secret` field.
This lets operators rotate the secret via env without restarting the
daemon.

The server SHOULD verify the signature with constant-time compare and
reject unsigned or invalid requests with 401.

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

- Network error / timeout / 5xx: CSM logs a warning and **proceeds with the default block**. The hook is fail-open.
- 200 OK with `verdict: "allow"`: CSM does **not** modify nftables; logs the override to stderr.
- 200 OK with `verdict: "block"` or omitted: standard block path runs (which still honors `auto_response.dry_run` if set).
- 200 OK with unknown `verdict` string: rejected; treated as fail-open (default block).

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
    json.NewEncoder(w).Encode(map[string]string{
        "verdict": verdict, "tenant_id": tenant,
    })
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

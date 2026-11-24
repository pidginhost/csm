# Verdict Callback HTTP Contract (v1)

When `auto_response.verdict_callback.enabled: true`, CSM POSTs eligible automatic block decisions to the configured URL and reads an advisory response. The endpoint lets phpanel observe and label decisions, downgrade them to audit-only, and attach tenant attribution. It is not a per-tenant nftables enforcement plane.

CSM runs its local block validation before calling the endpoint. It rejects these locally and does not send them to the callback:

- Malformed IPs.
- Disabled IPv6 targets.
- Infra IPs.
- Blocks refused by the configured block limits.

## Callers

Two parts of CSM call the endpoint. The request `source` tells them apart.

| `source` | Asks about | Effect of the answer |
|---|---|---|
| `auto_response` | An address CSM is about to block automatically. | An `allow` verdict skips that block. |
| `bpf_enforcement` | The destination of an outbound connection the BPF hook denied, or would have denied in dry run. | Annotates the finding only. |

### `auto_response`

CSM calls the endpoint for each automatic block of a single address. The call comes after local validation and before the `auto_response.dry_run` gate. `severity` is `"auto"`. An `allow` verdict skips that block.

### Extra `auto_response` requests in dry run

Admission is the part of CSM that decides whether an automatic block goes ahead. In dry run it records a forecast and blocks nothing.

In dry run, with the firewall on and outside observe mode, admission also asks the endpoint about locally eligible block attempts. One block can therefore bring an additional request. These requests:

- Carry `CSM auto-block: <check>` as the `reason`.
- Run up to four at a time.
- Honor `allow_unsigned` and `require_response_signature`.

An `allow` ends the forecast for that block attempt, and CSM stores no forecast example for it. Admission sends no request when a block already covers the address, when the target is protected, or when the forecast cannot admit or replace an entry in the full block set. A retry asks again, and a reload discards old policy answers.

The v1 request contains no dry-run field. Request totals are not an exact multiple of the calls from the older (legacy) blocking path.

### `bpf_enforcement`

CSM makes these calls only when `bpf_enforcement.verdict_callback: true` is also set. It asks about the destination of an outbound connection the BPF hook denied, or would have denied in dry run.

- `reason` is `bpf_enforcement:<check>:<port>`.
- `severity` is the finding's severity (`WARNING`, `HIGH` or `CRITICAL`).

The answer only annotates findings: CSM adds the verdict, `tenant_id` and `note` to the finding details. It never changes the kernel decision, which is made before the call.

CSM caches answers for one minute per destination, reason and severity. CSM emits the finding that triggers a lookup without the verdict, `tenant_id` and `note`.

### Blocks that do not call the endpoint

- Subnet blocks.
- Promotion of an existing block to permanent.
- Manual blocks from the CLI, web UI or API.

## Endpoint

```
POST <auto_response.verdict_callback.url>
Content-Type: application/json
Accept: application/json
X-CSM-Signature: sha256=<hex>          (HMAC-SHA256 over raw body, omitted if no secret configured)
```

`auto_response.verdict_callback.url` must be an `http://` or `https://` URL with a host. CSM POSTs directly to that URL and appends no path.

## Authentication

CSM signs the raw request body with HMAC-SHA256 using the configured secret. It sends the digest in `X-CSM-Signature: sha256=<hex>`.

The server MUST verify the signature with constant-time compare and reject unsigned or invalid requests with 401.

### Which secret CSM uses

CSM resolves the secret once per request/response exchange. If `hmac_secret_env` is set and the env var is non-empty, it wins over the static `hmac_secret` field. Request and response verification use the same key for that exchange.

The value comes from the running process environment. After you edit an environment file, restart the daemon; a configuration reload does not pick up the new value. See [credential rotation](credential-rotation.md).

### Running without a secret

CSM requires a non-empty `hmac_secret` or resolved `hmac_secret_env` value unless you enable `allow_unsigned`.

Set `allow_unsigned: true` only for staged rollouts that intentionally send unsigned requests and accept unsigned responses. Without a secret, CSM accepts an `allow` verdict only with that opt-in.

### Response signing (required by default)

The server MUST sign its response body with the same HMAC-SHA256 scheme: the same secret and the same `X-CSM-Signature: sha256=<hex>` header. CSM verifies the response signature with constant-time compare before it parses the verdict. It rejects an unsigned or forged response and falls back to its default block. Without this check an on-path attacker could downgrade every "block" decision to "allow".

If the server cannot sign responses yet, for example mid-rollout, set `auto_response.verdict_callback.require_response_signature: false` in `csm.yaml` to temporarily accept unsigned responses. The default is `true` when a secret is configured.

When response signing is disabled but a secret is configured, CSM still checks any `nonce` or `timestamp` fields the server echoes:

- A nonce must match the request nonce.
- A timestamp must stay within the five-minute skew window.
- A `block` reply can omit both fields. An `allow` reply must include at least one.

## Request body

```json
{
  "ip": "203.0.113.10",
  "reason": "mail_bruteforce",
  "severity": "auto",
  "source": "auto_response",
  "nonce": "9a7e84f0c123ab45e102d4f8b9c1d3e0",
  "timestamp": 1748345600
}
```

| Field | Sent | Value |
|---|---|---|
| `ip` | Required | The address CSM is about to block, or for `bpf_enforcement` the connection's destination. |
| `reason` | Required | Short reason string, for example `CSM auto-block: wp_login_bruteforce`. |
| `severity` | Optional | `"auto"` for auto-response decisions; the finding's severity for `bpf_enforcement`. |
| `source` | Optional | `"auto_response"` or `"bpf_enforcement"`; see [Callers](#callers). |
| `nonce` | Always sent | A 128-bit hex random value unique to this call. |
| `timestamp` | Always sent | Unix seconds when CSM produced the request. |

The panel MUST echo `nonce` verbatim when response signing is on. When response signing is disabled, CSM still checks the value if the panel echoes it.

The panel does not need to validate `timestamp` but MAY use it to reject stale calls.

## Response body (200 OK)

```json
{
  "verdict": "block",
  "tenant_id": "tenant-42",
  "note": "matched dovecot user pattern",
  "nonce": "9a7e84f0c123ab45e102d4f8b9c1d3e0",
  "timestamp": 1748345600
}
```

| Field | Required | Value |
|---|---|---|
| `verdict` | No | `"block"` or `"allow"`. An omitted field means `"block"`. |
| `tenant_id` | No | Attribution string. CSM logs it alongside the decision. |
| `note` | No | Free-form note logged for the verdict. |
| `nonce` | When response signing is on | MUST equal `request.nonce`. |
| `timestamp` | When response signing is on | Unix seconds when the panel produced the reply. |

`"block"` is the default verdict, and `"allow"` overrides it. CSM rejects any other string as a protocol error and treats it as "no decision": it proceeds with the default block, per fail-open semantics.

CSM compares `nonce` with constant-time equality and rejects mismatches as replay attempts. It rejects replies whose `timestamp` drifts more than five minutes from the local clock. With a configured secret, CSM checks these fields when present even if response signing is disabled.

## Failure semantics

On callback failure, automatic blocking follows local policy, including dry run. A failed BPF callback leaves the kernel decision unchanged. The table describes automatic blocks.

| Case | What CSM does |
|---|---|
| Network error, timeout or non-200 HTTP response | Logs a warning and proceeds with the default block. The hook is fail-open at the transport level. |
| Local nonce generation failure | Does not send the request and proceeds with the default block. |
| 200 OK with `verdict: "allow"` | Does not modify nftables and logs the override to stderr. If no HMAC secret is configured, this is accepted only when `allow_unsigned: true` is set. |
| 200 OK with `verdict: "block"` or omitted | Runs the standard block path, which still honors `auto_response.dry_run` if set. |
| 200 OK with unknown `verdict` string | Rejects it and treats it as fail-open (default block). |
| 200 OK with `verdict: "allow"` and no HMAC secret while `allow_unsigned` is false | Rejects it as an unsigned downgrade and treats it as fail-open (default block). |
| 200 OK with missing or invalid `X-CSM-Signature`, and `require_response_signature` not turned off | Rejects it as forged and treats it as fail-open (default block). |
| 200 OK with mismatched `nonce` or timestamp drift over five minutes | Rejects it as replay whenever a secret is configured and the field is present, and treats it as fail-open (default block). |
| 200 OK with missing `nonce` or `timestamp` | With a secret, requires both fields for signed-response mode and at least one for an `allow` in optional-signature mode. |

With a configured secret, signed JSON replies require both replay fields by default. An empty, correctly signed body carries no verdict.

Operators see a forged-response rejection in stderr. Recurring rejections indicate either a panel-side rollout gap or an active on-path attack.

## Limits

- CSM caps the response body at 64 KB. Larger responses are rejected.
- The default request timeout is 2 seconds. Set it with `timeout_sec`, range 1-30.

## Sample server stub (Go)

```go
http.HandleFunc("/api/csm/verdict", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    if !verifySignature(r.Header.Get("X-CSM-Signature"), body, secret) {
        http.Error(w, "bad signature", 401); return
    }
    var req struct {
        IP, Reason, Severity, Source string
        Nonce string
    }
    _ = json.Unmarshal(body, &req)

    tenant := lookupTenantOwning(req.IP) // your impl
    verdict := "block"
    if isPanelInfra(req.IP) {            // never block our own infra
        verdict = "allow"
    }
    respBody, _ := json.Marshal(map[string]any{
        "verdict": verdict, "tenant_id": tenant,
        "nonce": req.Nonce, "timestamp": time.Now().Unix(),
    })
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(respBody)
    w.Header().Set("X-CSM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
    _, _ = w.Write(respBody)
})
```

## When to graduate this to per-tenant enforcement

This v1 hook surfaces tenant attribution but does not synthesize per-tenant nftables rules. Real per-tenant enforcement would block IP X from tenant Y's mailboxes only and allow it elsewhere. If phpanel wants that, it is a separate plan that needs:

- Multi-set nftables rule generation per tenant.
- A way to map an IP and tenant pair to an nftables verdict.
- Lock-step config sync between CSM and the panel's tenant table.

Do that work then, against a real call site, not on spec.

# Crontab samples

Real user-crontab captures used as regression fixtures for
`CheckCrontabs` and `fixSuspiciousCrontab`.

Usernames and UIDs were replaced with placeholders (`victim1..5`,
`20001..20005`); all other bytes match the original attacker template.
The base64 blob on each line still decodes to the original victim's
path, so detections firing on the decoded shape continue to match.

## Inventory

| File | Pattern | Notes |
| ---- | ------- | ----- |
| `gsocket_defunct_kernel_01.crontab` | `exec -a '[kworker]'` disguise | kworker thread lookalike |
| `gsocket_defunct_kernel_02.crontab` | `exec -a '[ksmd]'` disguise | kernel same-page-merge daemon lookalike |
| `gsocket_defunct_kernel_03.crontab` | `exec -a '[slub_flushwq]'` disguise | slub allocator workqueue lookalike |
| `gsocket_defunct_kernel_04.crontab` | `exec -a '[raid5wq]'` disguise | md-raid workqueue lookalike |
| `gsocket_defunct_kernel_05.crontab` | `exec -a '[card0-crtc8]'` disguise | DRM card lookalike |
| `gsocket_b64_wrapped.crontab` | outer-base64 wrapped variant | surface text has zero markers; only `MatchCrontabPatternsDeep` finds them |
| `benign_01.crontab` | standard cron lines | must NOT match |

All malicious samples share: the `DO NOT REMOVE THIS LINE. SEED PRNG.
#defunct-kernel` header comment, the `{ echo <b64>|base64 -d|bash; }`
invocation, and the `GS_ARGS="-k ... -liqD"` gsocket/gs-netcat flags in
the decoded payload.

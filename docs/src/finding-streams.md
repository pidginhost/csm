# Recorded finding streams

Calibrating correlation (the coordinated-attack threshold, corroboration
grading, sequence rules) needs what a real host produced over days: every
finding with its check, severity, timestamp, owner and text, including the
false-positive floods and the long-lived rows that never clear. CSM already
writes that stream: every dispatched finding lands in
`/var/log/csm/audit.jsonl` (rotated copies are gzip files beside it). A
recorded stream is a copy of those files with every identity removed.

`scripts/finding-stream` turns the raw files into an anonymized stream:

```bash
# On the operator machine, after copying the files read-only from the host:
go run ./scripts/finding-stream anonymize \
    --salt-file .cache/finding-streams/salt \
    --out .cache/finding-streams/host-a.jsonl.gz \
    raw/audit.jsonl raw/audit.jsonl-*.gz
```

What the tool replaces, in every structured field and in free text:

- Host names become `host-<id>`, account names `acct-<id>`, domains
  `dom-<id>.example`, mailboxes `user-<id>@dom-<id>.example`. The `<id>` is
  derived from an HMAC of the value under a private salt, so the same salt
  maps one account to one pseudonym on every host and streams can be joined
  without knowing who is who. Names are replaced wherever they sit: in
  `/home/<account>/` paths, `Account:` lines, process context, LiteSpeed
  vhost tokens, and inside longer tokens such as `example.com-ssl_log` or
  `cp1.log`. The host's short name (its first label, when it carries a
  digit) maps to the same pseudonym as the full name. Any other token that
  looks like a domain (two or more labels, alphabetic last label that is
  not a file extension) is mapped too, even if no field named it; that
  over-reaches on a few dotted names like `options.option` and is accepted.
- IPv4 addresses map into 198.18.0.0/15 and IPv6 addresses into
  2001:db8::/32, both reserved and never routed, one address per raw value.
  Loopback addresses, system users such as `root` or `nobody`, and bare
  numeric uids are kept: they identify nobody and carry meaning.
- The details of a credential-leak finding are dropped entirely, and generic
  `password=`, `secret:` and `token=` material is blanked anywhere.
- Timestamps, check names, severities, finding ids, path structure below
  the account, plugin and file names, and process names are kept: they are
  what calibration reads.

Before writing, the tool scans its own output for every identity it learned
from structured fields, paths and mail addresses, and for any mailbox or
address outside the reserved ranges, and refuses to write if it finds one.
The scan looks at every span between label boundaries of every token, so a
name glued to underscores or file extensions is still found. The summary it
prints carries counts only and a fingerprint of the salt, never the salt.

Handling rules:

- Copy the audit files read-only (`tar` over `ssh`, or `scp`) into a local
  directory with mode 0700, run the tool, then delete the raw copies. Nothing
  runs on the monitored host.
- The salt file is created on first use with mode 0600. Keep it private and
  reuse it for every host whose stream should be joinable with the others;
  losing it makes new recordings unjoinable with old ones.
- Recorded streams stay outside the repository, under the ignored
  `.cache/finding-streams/` directory. A pseudonymized stream still describes
  real incidents on a real host, and this repository is public.

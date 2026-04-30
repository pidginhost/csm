package daemon

import "regexp"

// msgIDPattern guards exim -Mf invocations against header-injected garbage
// that slipped past parseHeaders. Exim msgIDs are <= 23 chars in practice
// but we accept up to 32 to allow for future format changes; the lower
// bound of 16 rules out any short string an attacker could try to slip in.
var msgIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{16,32}$`)

// eximBinary is resolved at module init via exec.LookPath. Empty means
// auto-action is permanently disabled (a Warning finding is emitted at
// startup -- see Phase O).
//
//nolint:unused // populated in K5 by AutoFreezePHPRelayQueue init via exec.LookPath
var eximBinary string

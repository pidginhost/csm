package daemon

// pkgManagerComms are the process names CSM treats as evidence that an
// observed sensitive-file write originated from a legitimate root-driven
// package transaction. The list intentionally omits shells (sh, bash) and
// generic utilities (cp, mv) -- attackers reuse those. Matching the package
// manager binary itself anywhere in the parent chain is the discriminator.
var pkgManagerComms = map[string]struct{}{
	"dnf":             {},
	"dnf-3":           {},
	"microdnf":        {},
	"yum":             {},
	"rpm":             {},
	"dpkg":            {},
	"apt":             {},
	"apt-get":         {},
	"unattended-upgr": {}, // unattended-upgrade is comm-truncated to TASK_COMM_LEN-1.
}

func isPackageManagerComm(comm string) bool {
	_, ok := pkgManagerComms[comm]
	return ok
}

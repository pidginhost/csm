package daemon

import "regexp"

// atomicWriteStageRE matches the `.temp.<digits>.<rest>` filename pattern
// emitted by cPanel's fileTransfer service and similar atomic-write
// helpers. The digits are a nanosecond timestamp; <rest> is the original
// basename that will be rename(2)d into place.
var atomicWriteStageRE = regexp.MustCompile(`^\.temp\.\d+\..+`)

// looksLikeAtomicWriteStage reports whether a base filename matches the
// atomic-write staging convention `.temp.<digits>.<name>`. Pass the
// basename, not the full path.
func looksLikeAtomicWriteStage(name string) bool {
	return atomicWriteStageRE.MatchString(name)
}

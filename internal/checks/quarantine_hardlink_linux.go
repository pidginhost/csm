//go:build linux

package checks

// hardlinkWarningSupported reports whether quarantine reports a completed
// action that left another name pointing at the malicious inode. Only the
// Linux transaction detects a surviving hard link; the portable path used by
// developer machines copies and unlinks without inspecting the link count.
const hardlinkWarningSupported = true

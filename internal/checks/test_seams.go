package checks

// SetAccountHomeRootsForTest points account-root discovery at roots and
// returns a function that restores the previous source. For tests only.
func SetAccountHomeRootsForTest(roots []string) (restore func()) {
	prev := accountHomeRoots
	accountHomeRoots = func() []string { return roots }
	return func() { accountHomeRoots = prev }
}

// SetQuarantineDirForTest redirects quarantine moves to dir and returns a
// function that restores the previous directory. For tests only.
func SetQuarantineDirForTest(dir string) (restore func()) {
	prev := quarantineDir
	quarantineDir = dir
	return func() { quarantineDir = prev }
}

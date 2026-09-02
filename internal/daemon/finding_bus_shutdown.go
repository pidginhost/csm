package daemon

// closeFindingBus closes the finding broadcast bus at shutdown and leaves it
// installed in alert.FindingBus. Close turns Publish into a no-op, which is
// all shutdown needs; clearing the package-level interface as well raced
// the untracked control-socket and web UI goroutines that read it inside
// alert.Dispatch (a torn interface read is a nil-receiver panic).
func (d *Daemon) closeFindingBus() {
	if d.findingBus != nil {
		d.findingBus.Close()
	}
}

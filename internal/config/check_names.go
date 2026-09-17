package config

// CanonicalCheckName maps persisted check names to the current finding names.
// Config exclusions, saved mutes and pending work must survive a producer rename.
func CanonicalCheckName(name string) string {
	switch name {
	case "ftp_login_realtime":
		return "ftp_login"
	case "ssh_login_realtime":
		return "ssh_login_unknown_ip"
	default:
		return name
	}
}

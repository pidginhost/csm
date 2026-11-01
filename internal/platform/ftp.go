package platform

// FTPServerInstalled reports whether the host has an FTP server that needs
// a passive port range: every cPanel host ships one, elsewhere pure-ftpd,
// proftpd or vsftpd must be installed. An installed server counts even when
// stopped, so its ports are open before it starts.
func FTPServerInstalled() bool {
	if pathExists("/usr/local/cpanel/version") {
		return true
	}
	// Plesk renames ProFTPD, and Debian's Pure-FTPd authentication packages
	// install distinct server binaries instead of the vanilla executable.
	return binaryInstalled([]string{
		"pure-ftpd", "pure-ftpd-mysql", "pure-ftpd-postgresql", "pure-ftpd-ldap",
		"proftpd", "in.proftpd", "vsftpd",
	}, []string{
		"/usr/sbin/pure-ftpd",
		"/usr/sbin/pure-ftpd-mysql",
		"/usr/sbin/pure-ftpd-postgresql",
		"/usr/sbin/pure-ftpd-ldap",
		"/usr/sbin/proftpd",
		"/usr/sbin/in.proftpd",
		"/usr/sbin/vsftpd",
	})
}

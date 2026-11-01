package platform

// FTPServerInstalled reports whether the host has an FTP server that needs
// a passive port range: every cPanel host ships one, elsewhere pure-ftpd,
// proftpd or vsftpd must be installed. An installed server counts even when
// stopped, so its ports are open before it starts.
func FTPServerInstalled() bool {
	if pathExists("/usr/local/cpanel/version") {
		return true
	}
	return binaryInstalled([]string{"pure-ftpd", "proftpd", "vsftpd"}, []string{
		"/usr/sbin/pure-ftpd",
		"/usr/sbin/proftpd",
		"/usr/sbin/vsftpd",
	})
}

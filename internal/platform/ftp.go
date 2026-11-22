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
	return PureFTPDInstalled() || binaryInstalled([]string{
		"proftpd", "in.proftpd", "vsftpd",
	}, []string{
		"/usr/sbin/proftpd",
		"/usr/sbin/in.proftpd",
		"/usr/sbin/vsftpd",
	})
}

// PureFTPDInstalled reports whether a pure-ftpd server binary is installed,
// including the variants Debian's authentication packages provide.
func PureFTPDInstalled() bool {
	names := PureFTPDBinaries()
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = "/usr/sbin/" + name
	}
	return binaryInstalled(names, paths)
}

// PureFTPDBinaries names the pure-ftpd server executables, including the
// variants Debian's authentication packages provide.
func PureFTPDBinaries() []string {
	return []string{"pure-ftpd", "pure-ftpd-mysql", "pure-ftpd-postgresql", "pure-ftpd-ldap"}
}

// PureFTPDServerTitle identifies the standalone listener, not an inetd session.
const PureFTPDServerTitle = "pure-ftpd (SERVER)"

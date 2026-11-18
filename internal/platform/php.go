package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// phpBinaryGlobs are the places the supported stacks install a PHP
// interpreter: distro packages, cPanel EA4, CloudLinux alt-php, LiteSpeed
// lsphp, Plesk, DirectAdmin and Remi. The patterns name the interpreter
// binaries themselves, not helpers such as phpenmod that php-common can
// leave behind after PHP is removed.
var phpBinaryGlobs = []string{
	"/usr/bin/php",
	"/usr/bin/php[0-9]*",
	"/usr/bin/php-cgi*",
	"/usr/sbin/php-fpm*",
	"/usr/local/bin/php",
	"/usr/local/bin/php-cgi*",
	"/usr/local/sbin/php-fpm*",
	"/opt/cpanel/ea-php*/root/usr/bin/php",
	"/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
	"/opt/alt/php*/usr/bin/php",
	"/opt/alt/php*/usr/sbin/php-fpm",
	"/usr/local/lsws/lsphp*/bin/lsphp",
	"/usr/local/lsws/fcgi-bin/lsphp*",
	"/opt/plesk/php/*/bin/php",
	"/opt/plesk/php/*/sbin/php-fpm",
	"/usr/local/php*/bin/php",
	"/usr/local/php*/sbin/php-fpm",
	"/opt/remi/php*/root/usr/bin/php",
	"/opt/remi/php*/root/usr/sbin/php-fpm",
}

// DetectPHP reports whether any PHP interpreter is installed on this host.
// It only stats files, so callers may run it on every feature refresh.
func DetectPHP() bool { return detectPHP("/") }

func detectPHP(root string) bool {
	if detectPHPUnder(root) {
		return true
	}
	_, err := exec.LookPath("php")
	return err == nil
}

// detectPHPUnder looks for a PHP interpreter below root.
func detectPHPUnder(root string) bool {
	for _, pattern := range phpBinaryGlobs {
		matches, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, m := range matches {
			if phpBinaryName.MatchString(filepath.Base(m)) && isExecutableFile(m) {
				return true
			}
		}
	}
	return false
}

var phpBinaryName = regexp.MustCompile(`^(php(-cgi|-fpm)?|lsphp)([0-9]+(\.[0-9]+)*)?$`)

// IsPHPServerBinary reports whether name identifies a PHP-FPM or LiteSpeed interpreter.
func IsPHPServerBinary(name string) bool {
	return (strings.HasPrefix(name, "php-fpm") || strings.HasPrefix(name, "lsphp")) && phpBinaryName.MatchString(name)
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

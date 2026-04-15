package checks

import (
	"testing"
)

// These are fuzz targets for the string parsers that accept external input
// (log lines, finding messages, wp-config bodies, /proc/net/tcp rows).
// Each target just asserts that the function returns without panicking on
// any input -- the goal is crash-finding, not output verification.
//
// Run the seed corpus with `go test -run=Fuzz`. Run actual fuzzing with
// `go test -fuzz=FuzzFoo -fuzztime=30s ./internal/checks/` during
// investigation.

func FuzzExtractIPAfterKeyword(f *testing.F) {
	// Seeds cover the shapes the function sees in real logs.
	f.Add("Accepted publickey for root from 203.0.113.5 port 22", "from")
	f.Add("rip=198.51.100.99, lip=10.0.0.1", "rip=")
	f.Add("", "")
	f.Add("keyword at the end keyword=", "keyword=")
	f.Add("ipv6 from 2001:db8::1 port 22", "from")
	f.Fuzz(func(t *testing.T, line, keyword string) {
		_ = extractIPAfterKeyword(line, keyword)
	})
}

func FuzzExtractBracketedIP(f *testing.F) {
	f.Add("H=client [203.0.113.50]:2222 auth failed")
	f.Add("no bracket here")
	f.Add("[1.2.3.4]")
	f.Add("[")
	f.Add("[unclosed bracket")
	f.Add("[][][][]")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractBracketedIP(line)
	})
}

func FuzzFirstField(f *testing.F) {
	f.Add("203.0.113.5 - - [14/Apr/2026:10:00:00 +0000] \"GET /\"")
	f.Add("2001:db8::1 rest of line")
	f.Add("not-an-ip first field here")
	f.Add("")
	f.Add("   ")
	f.Fuzz(func(t *testing.T, line string) {
		_ = firstField(line)
	})
}

func FuzzExtractPID(f *testing.F) {
	f.Add("PID: 12345, exe=/bin/ls")
	f.Add("info before PID: 999 trailing")
	f.Add("PID: 42")
	f.Add("PID: 7\nlater")
	f.Add("no pid here")
	f.Add("PID: ")
	f.Fuzz(func(t *testing.T, details string) {
		_ = extractPID(details)
	})
}

func FuzzExtractFilePath(f *testing.F) {
	f.Add("webshell at /home/u/public_html/x.php was found")
	f.Add("file in /dev/shm/y.so")
	f.Add("comma terminator: /home/a/b.php, more")
	f.Add("no path mentioned")
	f.Add("")
	f.Add("/home/")
	f.Add("/var/tmp/")
	f.Fuzz(func(t *testing.T, message string) {
		_ = extractFilePath(message)
	})
}

func FuzzExtractEximMsgID(f *testing.F) {
	f.Add("phishing detected (message: 2jKPFm-000abc-1X) blah")
	f.Add("no marker")
	f.Add("(message: open-but-no-close")
	f.Add("(message: )")
	f.Add("(message: ../../etc/passwd)")
	f.Fuzz(func(t *testing.T, message string) {
		_ = extractEximMsgID(message)
	})
}

func FuzzExtractPHPDefine(f *testing.F) {
	f.Add("define( 'DB_NAME', 'mydb' );")
	f.Add("define(\"DB_USER\", \"root\");")
	f.Add("define('DISABLE_WP_CRON', true);")
	f.Add("define('WP_MEMORY_LIMIT', 256);")
	f.Add("// commented out")
	f.Add("")
	f.Add("define(")
	f.Add("define(,,,,)")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractPHPDefine(line)
	})
}

func FuzzExtractPHPString(f *testing.F) {
	f.Add(" 'hello');")
	f.Add(` "world");`)
	f.Add(`'first' "second"`)
	f.Add(`'unclosed "fallback";`)
	f.Add("no quotes here")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_ = extractPHPString(s)
	})
}

func FuzzParseHexAddr(f *testing.F) {
	// /proc/net/tcp column 1 / 2 format: hex_ip:hex_port
	f.Add("01010101:0035")
	f.Add("0100007F:ABCD")
	f.Add("00000000:0000")
	f.Add("")
	f.Add(":")
	f.Add("zzzz:zzzz")
	f.Add("0123456789ABCDEF01234567:0050") // IPv6-ish
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseHexAddr(s)
	})
}

func FuzzDecodeHexString(f *testing.F) {
	f.Add("")
	f.Add("6c73") // "ls"
	f.Add("odd-length-not-hex")
	f.Add("g0ff") // non-hex char
	f.Add("0000") // all zeros
	f.Fuzz(func(t *testing.T, s string) {
		_ = decodeHexString(s)
	})
}

func FuzzParseDBFindingDetails(f *testing.F) {
	f.Add("Database: alice_wp\nOption: siteurl")
	f.Add("no match at all")
	f.Add("Database: only-db")
	f.Add("Option: only-option")
	f.Add("")
	f.Fuzz(func(t *testing.T, details string) {
		_, _ = parseDBFindingDetails(details)
	})
}

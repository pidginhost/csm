package daemon

import (
	"io/fs"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func FuzzPHPRelayScriptPath(f *testing.F) {
	for _, suffix := range []string{"", "5", "mailer.php", "/wp-cron.php", "/wp-admin/post.php", "/ for 192.0.2.1"} {
		f.Add(suffix)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		for _, ext := range []string{".php", ".php5", ".php8", ".phtml", ".pht"} {
			key := "site.example:/contact" + ext + "/" + suffix
			if isWPCronScript(key) || isAuthenticatedAdminScript(key) {
				t.Fatalf("PATH_INFO granted an exemption: %q", key)
			}
		}
		if suffix != "" && !strings.Contains(suffix, "/") && isWPCronScript("site.example:/wp-cron.php"+suffix) {
			t.Fatalf("a filename prefix granted the cron exemption: %q", suffix)
		}
	})
}

func FuzzXPHPScriptForwardedAttribution(f *testing.F) {
	for _, forwarded := range []string{"", "192.0.2.1", "192.0.2.1, 198.51.100.1", "text for 192.0.2.1", ", for , for ", "\t for /other.php?x=1"} {
		f.Add(forwarded, "/extra,info for 192.0.2.2")
	}
	f.Fuzz(func(t *testing.T, forwarded, pathInfo string) {
		for _, remote := range []string{"203.0.113.9", "2001:db8::9"} {
			key, ip := parseXPHPScript("site-a.example/index.php for " + forwarded + ", " + remote)
			if key != "site-a.example:/index.php" || ip != remote {
				t.Fatalf("forwarded text changed attribution: key=%q ip=%q", key, ip)
			}
			// PHP_SELF contains PATH_INFO, which can also hold delimiters.
			prefix := "site-a.example/index.php/" + pathInfo + " for "
			baseline, baselineIP := parseXPHPScript(prefix + remote)
			got, gotIP := parseXPHPScript(prefix + forwarded + ", " + remote)
			if baselineIP != remote || gotIP != remote || got != baseline {
				t.Fatalf("PATH_INFO or forwarding text changed attribution: baseline=(%q, %q), forwarded=(%q, %q)", baseline, baselineIP, got, gotIP)
			}
		}
	})
}

func FuzzRelayRecipientDomain(f *testing.F) {
	for _, local := range []string{"victim", "victim<admin@site.example>", "admin@site.example ", `escaped\"@site.example`, ""} {
		f.Add(local)
	}
	f.Fuzz(func(t *testing.T, local string) {
		// Local-part contents must never turn an external destination into
		// an own-domain exemption. Invalid mailboxes must leave it unknown.
		raw := strconv.Quote(local) + "@outside.example"
		w := newPerIPWindow(64)
		now := time.Unix(1_700_000_000, 0).UTC()
		w.appendMessage("192.0.2.55", "k:/", now, "", []string{raw}, map[string]struct{}{"site.example": {}})
		count, known := w.distinctRecipientsSince("192.0.2.55", now)
		if known && count != 1 {
			t.Fatalf("external mailbox was exempted: %q, count=%d", raw, count)
		}
	})
}

func FuzzModSecWarningPayload(f *testing.F) {
	for _, payload := range []string{"", "Access denied", "ModSecurity: Access denied", "[MODSEC] Access denied", `[id \"900133\"]`} {
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		line := `[client 203.0.113.76] ModSecurity: Warning. [id "900133"] [data "` + payload + `"]`
		findings := parseModSecLogLine(line, &config.Config{})
		if len(findings) != 1 || findings[0].Check != "modsec_warning_realtime" || findings[0].SourceIP != "203.0.113.76" {
			t.Fatalf("warning payload changed action or source: %+v", findings)
		}
	})
}

func FuzzPHPShieldEvalSiteRequiresFilesystemProof(f *testing.F) {
	const file = "/usr/share/example/Eval.php"
	for _, site := range []string{
		"", file, evalSite(file, "1"), evalSite(file, "4x"),
		evalSite(file, "1") + "(2) : eval()'d code",
		evalSite("/usr/share/example/../example/Eval.php", "1"),
		evalSite("/usr/share/example/Eval.php\x00", "1"),
	} {
		f.Add(site, uint32(0), uint32(0o644))
	}
	f.Add(evalSite(file, "1"), uint32(1001), uint32(0o644))
	f.Add(evalSite(file, "1"), uint32(0), uint32(0o666))
	f.Add(evalSite(file, "1"), uint32(0), uint32(fs.ModeSymlink|0o644))
	f.Fuzz(func(t *testing.T, site string, uid, mode uint32) {
		info := fakeEvalSiteInfo{name: "Eval.php", mode: fs.FileMode(mode), uid: uid}
		useFakeEvalSiteTree(t, fakeEvalSiteTree{file: info})
		if phpShieldEvalSiteIsSystemCode(site) && (uid != 0 || !info.mode.IsRegular() || info.mode.Perm()&0o022 != 0) {
			t.Fatalf("untrusted filesystem metadata demoted eval site: %q uid=%d mode=%v", site, uid, info.mode)
		}
	})
}

func FuzzBackWPupJobState(f *testing.F) {
	for _, head := range []string{
		"", backwpupWorking, backwpupFolderRaw,
		"<?php\r\n///home/alice/\r\n//",
		"<?php\n///home/alice/\recho 1;",
		"<?php //{\"job\":\"?><?=1?>\"}",
		"<?php\n///home/alice/\n#[Attr] function f() {}",
	} {
		f.Add([]byte(head))
	}
	f.Fuzz(func(t *testing.T, head []byte) {
		// Leave room for the escape inside the retained window, so this
		// checks visible code rather than the intentionally unknown tail.
		if len(head) > dropperTrackedHeadMax-32 {
			head = head[:dropperTrackedHeadMax-32]
		}
		for _, name := range []string{"backwpup-working.php", "backwpup-ced7cc-folder.php"} {
			for _, escape := range []string{"\necho 1;", "\recho 1;", "?><?=1?>", "\n#[Attr] function f() {}"} {
				body := append(append([]byte(nil), head...), escape...)
				if looksLikeBackWPupJobState(name, body) {
					t.Fatalf("visible code demoted as backup state: %q", body)
				}
			}
		}
	})
}

func FuzzModSecRuleFileConfidence(f *testing.F) {
	f.Add(211999, "Unknown vendor rule", "", `[file "/rules/anomaly-content-type.conf"]`)
	f.Add(942190, "", "", liteSpeedTriggerLineCRSSQLi)
	f.Add(942100, "SQL Injection Attack Detected", "attack-sqli", `[file "/rules/REQUEST-949-BLOCKING-EVALUATION.conf"]`)
	f.Add(949110, "Inbound Anomaly Score Exceeded", "anomaly-evaluation", `[file "/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]`)
	f.Add(900100, "", "", `] at [unclosed`)
	f.Fuzz(func(t *testing.T, rule int, msg, tags, line string) {
		baseline := classifyModSecConfidence(rule, msg, tags, "")
		got := classifyModSecConfidence(rule, msg, tags, extractModSecRuleFile(line))
		// File evidence may promote any class to high. It must never turn
		// an unknown deny into low-confidence policy or demote an attack.
		if got != baseline && got != modsecConfHigh {
			t.Fatalf("rule file changed confidence from %v to %v: %q", baseline, got, line)
		}
	})
}

func FuzzDropperContentIsInert(f *testing.F) {
	for _, head := range []string{"", "<?php // guard", "<?php # guard\r", "<?php /*", "<?php ?><?=1?>", "<?php // +AAo-echo 1;", "<?php /* \xc2\xa0 */", "<?php // =0Aecho 1;", "<?php //AAAPD9waHAgZWNobyAxOyAg"} {
		f.Add([]byte(head))
	}
	f.Fuzz(func(t *testing.T, head []byte) {
		if dropperContentIsInert(head, int64(len(head))+1) {
			t.Fatal("partial content declared inert")
		}
		// Close any comment before adding a new PHP block. The trailing
		// statement must never disappear behind an earlier closing tag.
		withCode := append(append([]byte(nil), head...), []byte("\n*/\r\n?><?php echo 1;")...)
		if dropperContentIsInert(withCode, int64(len(withCode))) {
			t.Fatalf("trailing code declared inert: %q", withCode)
		}
	})
}

func FuzzAtomicWriteContentPath(f *testing.F) {
	for _, path := range []string{"/home/site/.temp.1.example.php", "/home/site/.temp.1..htaccess", "/home/site/.temp.1...", ".temp.1..", "", "/", ".temp.1.\x00"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		got := atomicWriteContentPath(path)
		if filepath.Dir(got) != filepath.Dir(path) {
			t.Fatalf("content hint escaped parent: %q -> %q", path, got)
		}
		if !looksLikeAtomicWriteStage(filepath.Base(path)) && got != path {
			t.Fatalf("ordinary name changed: %q -> %q", path, got)
		}
	})
}

// Fuzz targets for daemon-side log parsers. Same approach as
// internal/checks/fuzz_parsers_test.go: find crashers, don't verify output.

func FuzzParseDovecotLoginFields(f *testing.F) {
	f.Add("... Login: user=<alice@example.com>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1")
	f.Add("Login: user=<alice>, rip=1.2.3.4")
	f.Add("no login here")
	f.Add("user=<")
	f.Add("user=<unclosed")
	f.Add("rip=")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseDovecotLoginFields(line)
	})
}

func FuzzExtractMailHoldSender(f *testing.F) {
	f.Add("Sender user@domain has an outgoing mail hold")
	f.Add("Domain example.com has an outgoing mail hold")
	f.Add("Sender ")
	f.Add("Domain ")
	f.Add("no sender marker")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractMailHoldSender(line)
	})
}

func FuzzParseSPFDMARCRejection(f *testing.F) {
	f.Add("2024-01-01 H=mail [203.0.113.5] F=<a@evil.com> ** <b@victim.com> : SPF check failed")
	f.Add("R=dnslookup ** <user@example.com> : 5.7.1 DMARC alignment failure")
	f.Add(" ** <user@example.com> : DKIM signature invalid")
	f.Add(" ** <@nodomain> : spf")
	f.Add(" ** <user@> : dmarc")
	f.Add(" ** <user@domain>")
	f.Add(" ** no brackets : spf")
	f.Add("no star marker at all")
	f.Add(" ** <a@b> : ")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseSPFDMARCRejection(line)
	})
}

func FuzzExtractPureFTPDClientIP(f *testing.F) {
	f.Add("pure-ftpd: (?@203.0.113.5) [INFO] Login failed")
	f.Add("pure-ftpd: (user@2001:db8::1) [INFO] ok")
	f.Add("(noatsign)")
	f.Add("(user@not-an-ip)")
	f.Add("(user@203.0.113.5")
	f.Add("user@203.0.113.5)")
	f.Add("(@)")
	f.Add("plain log line")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractPureFTPDClientIP(line)
	})
}

func FuzzParseSessionNew(f *testing.F) {
	for _, line := range []string{
		sessionNewLine("cpaneld", "203.0.113.5", "alice"),
		sessionNewLine("webmaild", "2001:db8::5", "office@example.com"),
		"[2026-11-05 09:00:00 +0000] info [whostmgrd] 203.0.113.5 NEW x[cpaneld]:tok address=[webmaild] 203.0.113.6 NEW bob:tok",
		"[2026-11-05 09:00:00 +0000] info [cpaneld] 203.0.113.5 PURGE alice:tok logout",
		"[2026-11-05 09:00:00 +0000] info [cpaneld] 203.0.113.5 NEW :tok",
		"[cpaneld] 203.0.113.5 NEW alice:tok",
		"[]",
		"",
	} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		app, ip, account, ok := parseSessionNew(line)
		if !ok {
			return
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			t.Fatalf("accepted address %q: %v", ip, err)
		}
		if account == "" || strings.ContainsAny(account, ": \t\r\n") {
			t.Fatalf("accepted account %q", account)
		}
		if app != "cpaneld" && app != "webmaild" {
			t.Fatalf("accepted app %q", app)
		}
	})
}

func FuzzCustomerLoginTime(f *testing.F) {
	f.Add("[2026-11-05 09:00:00 +0000] info [cpaneld]")
	f.Add("2026-11-05T09:00:00Z host dovecot:")
	f.Add("Nov  5 09:00:00 host dovecot:")
	f.Add("2026-11-05 09:00:00 1abc23-000456-AB <=")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
		want := now.Add(-time.Hour)
		for _, prefix := range []string{
			"[2026-11-05 09:00:00 +0000]",
			"2026-11-05T09:00:00Z",
			"Nov  5 09:00:00",
			"2026-11-05 09:00:00",
		} {
			if got := customerLoginTime(prefix+" host "+line, now); !got.Equal(want) {
				t.Fatalf("message text replaced the source time: %v, want %v", got, want)
			}
		}
	})
}

func FuzzIsPrivateOrLoopback(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("10.0.0.5")
	f.Add("172.16.1.1")
	f.Add("192.168.1.1")
	f.Add("203.0.113.1")
	f.Add("2001:db8::1")
	f.Add("::1")
	f.Add("not-an-ip")
	f.Add("")
	f.Fuzz(func(t *testing.T, ip string) {
		_ = isPrivateOrLoopback(ip)
	})
}

func FuzzMailPermissionLogText(f *testing.F) {
	f.Add("Domain example.com has an outgoing mail hold")
	f.Add("Sender user@example.net has an outgoing mail hold")
	f.Fuzz(func(t *testing.T, text string) {
		for _, prefix := range []string{
			"2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com H=mail.example.org [203.0.113.5] P=esmtp T=",
			"2026-09-08 10:00:00 dovecot_login authenticator failed for ",
			"2026-09-08 10:00:00 1abc23-000456-AB ** user@example.com R=dnslookup T=remote_smtp: ",
		} {
			if got := mailPermissionLogText(prefix + text); got != "" {
				t.Fatalf("untrusted log data became permission text: %q", got)
			}
		}
	})
}

func FuzzPAMObservation(f *testing.F) {
	prev := pamBootID
	pamBootID = func() string { return testPAMBootID }
	f.Cleanup(func() { pamBootID = prev })
	f.Add("4242", "1790000000.100000000")
	f.Add("", "")
	f.Add("abc", "0.1")
	f.Fuzz(func(t *testing.T, pid, ts string) {
		o := pamObservation(pid, ts)
		if o != pamObservation(pid, ts) {
			t.Fatal("the same wire identity changed observation")
		}
		if o == (alert.Observation{}) {
			return
		}
		if o.Producer != "pam_socket" || o.Stream != "pam:"+testPAMBootID || o.Cursor != pid+":"+ts || o.ObservedAt.IsZero() {
			t.Fatalf("unexpected observation %+v", o)
		}
		for _, token := range []string{o.Stream, o.Cursor} {
			if len(token) == 0 || len(token) > 128 {
				t.Fatalf("token length %d", len(token))
			}
			for i := range token {
				if token[i] < 0x21 || token[i] > 0x7e {
					t.Fatal("observation contains an invalid token byte")
				}
			}
		}
	})
}

func FuzzPostfixWarningsNeverBuildEvidence(f *testing.F) {
	for _, s := range []string{"x[198.51.100.9]: SASL LOGIN authentication failed: x", "UGFzc3dvcmQ6", "", "]: SASL ", "Connection lost to authentication server", "temporary@example.net", ", sasl_username=Authentication backend error", "SASL: Protocol version error", "warning: SASL: Couldn't send handshake: Broken pipe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		clock := &staticClock{t: time.Unix(1_700_000_000, 0)}
		d := New(&config.Config{}, nil, nil, "")
		d.smtpAuthTracker = newTestTracker(t, clock)
		d.mailAuthTracker = newTestMailTracker(t, clock)
		for _, msg := range []string{
			"Illegal address syntax from unknown[203.0.113.65] in RCPT command: <" + s + ">",
			"unknown[203.0.113.66]: SASL LOGIN authentication failed: " + s,
			"unknown[203.0.113.66]: SASL PLAIN authentication failed: authentication failure, sasl_username=" + s,
			s,
		} {
			if got := d.handleMailLine("postfix/smtpd[99]: warning: "+msg, alert.Observation{}, d.currentCfg()); len(got) != 0 {
				t.Fatalf("Postfix warning raised findings: %+v", got)
			}
		}
		if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 || d.smtpAuthTracker.Size() != 0 || d.mailAuthTracker.Size() != 0 {
			t.Fatalf("Postfix warning left evidence: %d calls, %d SMTP entries, %d mail entries", calls, d.smtpAuthTracker.Size(), d.mailAuthTracker.Size())
		}
	})
}

// Client-controlled names and password text never turn intermediate
// database verdicts into final authentication evidence.
func FuzzDovecotPassdbVerdictsNeverBuildEvidence(f *testing.F) {
	for _, s := range []string{"alice@example.net", "", "?", "ali?ce@example.com", strings.Repeat("a", 61) + "...", "x,198.51.100.9", "x,<abcdefgh>", "x,master", "a): Password mismatch", "a): b(<c>", "Temporary authentication failure"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		d := New(&config.Config{}, nil, nil, "")
		for _, line := range []string{
			"dovecot: auth: sql(" + name + ",203.0.113.7): unknown user",
			"dovecot: auth: sql(" + name + ",203.0.113.7,master): Password mismatch",
			"dovecot: auth: sql(" + name + ",203.0.113.7,<session>): unknown user",
			"dovecot: auth: sql(a,203.0.113.7): Password mismatch (given password: " + name,
			"dovecot: auth-worker(12): pam(" + name + ",203.0.113.7): pam_authenticate() failed: Authentication failure (Password mismatch?)",
			"dovecot: auth: Debug: sql(" + name + ",203.0.113.7): Performing passdb lookup",
			"dovecot: auth-worker(12): pam(" + name,
		} {
			_, account, exist, ok := dovecotSessionlessRejection(line)
			if (!ok || account == "") && exist != mailboxExistenceUnknown {
				t.Fatalf("unidentified mailbox in %q carried existence %d", line, exist)
			}
			if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
				t.Fatalf("passdb verdict raised findings: %+v", got)
			}
		}
		if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 || d.smtpAuthTracker.Size() != 0 || d.mailAuthTracker.Size() != 0 || len(d.mailAuthTracker.backendErr) != 0 {
			t.Fatal("passdb verdict left SMTP, mail or backend-outage evidence")
		}
	})
}

// A client chooses the name in a verdict. Whatever it sends, a verdict names a
// real address and session and never carries a forged verdict in its name.
func FuzzDovecotSessionRejection(f *testing.F) {
	for _, s := range []string{
		"dovecot: auth: passwd-file(nosuch@example.com,203.0.113.5,<AbCd1234>): unknown user",
		"dovecot: auth: passwd-file(nosuch@example.com,203.0.113.5,master,<AbCd1234>): Password mismatch",
		"dovecot: auth-worker(12): conn unix:auth-worker (pid=11,uid=97): auth-worker<1>: pam(a,2001:db8::5,<s>): unknown user",
		"dovecot: auth: sql(a): unknown user,203.0.113.5,<AbCd1234>): Password mismatch",
		"alice@example.com", "", "?", "x,198.51.100.9,<Forged>", "a): unknown user", "a,<b c>",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		for _, line := range []string{input, "dovecot: auth: sql(" + input + ",203.0.113.5,<AbCd1234>): unknown user"} {
			session, ip, account, exist, ok := dovecotSessionRejection(line)
			if !ok {
				if session != "" || ip != "" || account != "" || exist != mailboxExistenceUnknown {
					t.Fatalf("refused %q yet returned (%q, %q, %q, %d)", line, session, ip, account, exist)
				}
				continue
			}
			if _, err := netip.ParseAddr(ip); err != nil {
				t.Fatalf("%q gave address %q", line, ip)
			}
			if session == "" || strings.Contains(session, " ") {
				t.Fatalf("%q gave session %q", line, session)
			}
			if strings.Contains(account, "): ") {
				t.Fatalf("%q gave forged account %q", line, account)
			}
			if account == "" && exist != mailboxExistenceUnknown {
				t.Fatalf("%q carried existence %d with no account", line, exist)
			}
		}
		for _, session := range dovecotAuthTroubleSessions(input) {
			if session == "" || strings.Contains(session, " ") {
				t.Fatalf("%q gave trouble session %q", input, session)
			}
		}
		line := "dovecot: auth: Error: sql(" + input + ",203.0.113.5,<AbCd1234>): Password query failed"
		if !slices.Contains(dovecotAuthTroubleSessions(line), "AbCd1234") {
			t.Fatalf("name %q hid the session of an auth error", input)
		}
	})
}

func FuzzDovecotLoginSession(f *testing.F) {
	for _, name := range []string{"alice@example.com", "a session=<Forged>", "a>, rip=198.51.100.9, session=<Forged>"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		prefix := "dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<" + name + ">, rip=203.0.113.5, lip=192.0.2.1"
		for suffix, want := range map[string]string{"": "", ", session=<Cut": "", ", session=<Real>": "Real"} {
			if got := dovecotLoginSession(prefix + suffix); got != want {
				t.Fatalf("name %q, suffix %q: session = %q, want %q", name, suffix, got, want)
			}
		}
	})
}

// A client chooses its login name and, through its HELO and rDNS, text that
// smtpd echoes. Pairing still only counts the address Dovecot appended, and a
// verdict pairs once.
func FuzzSMTPAuthPairingAddress(f *testing.F) {
	for _, s := range []string{"alice@example.net", "", "x,198.51.100.9", "x[198.51.100.9]", "x): unknown user", ", sasl_username=", "unknown[198.51.100.9]: SASL LOGIN authentication failed: x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		clock := &staticClock{t: time.Unix(1_700_000_000, 0)}
		d := New(&config.Config{}, nil, nil, "")
		d.smtpAuthTracker = newTestTracker(t, clock)
		for _, line := range []string{
			"dovecot: auth: sql(" + name + ",203.0.113.7): unknown user",
			"postfix/smtpd[9]: warning: unknown[198.51.100.9]: SASL LOGIN authentication failed: x, sasl_username=" + name,
			"postfix/smtpd[9]: warning: " + name + "[198.51.100.9]: SASL LOGIN authentication failed: x",
			"postfix/smtpd[9]: warning: Illegal address syntax from unknown[198.51.100.9] in RCPT command: <" + name + ">",
			"postfix/smtpd[9]: warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: x",
			"postfix/smtpd[9]: warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: x",
		} {
			clock.advance(time.Second)
			d.handleMailLine(line, alert.Observation{}, d.currentCfg())
		}
		if calls, _ := d.smtpAuthTracker.Stats(); calls > 1 {
			t.Fatalf("one verdict counted %d times", calls)
		}
		for ip := range d.smtpAuthTracker.ips {
			if ip != "203.0.113.7" {
				t.Fatalf("name %q counted a failure for %s", name, ip)
			}
		}
	})
}

func FuzzSMTPAuthTroublePrefix(f *testing.F) {
	for _, s := range []string{"SASL: Protocol version error", "warning: SASL: Couldn't send handshake: Broken pipe", "", "\npostfix/smtpd[99]: warning: SASL: error"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, clientText string) {
		d, clock := newPairingDaemon(t, &config.Config{})
		feed(d, clock,
			"postfix/smtpd[99]: warning: Illegal address syntax from unknown[203.0.113.65] in RCPT command: <"+clientText+">",
			"postfix/smtpd[99]: warning: unknown[203.0.113.65]: SASL LOGIN authentication failed: x, sasl_username="+clientText,
			"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
			"postfix/smtpd[99]: warning: unknown[203.0.113.95]: SASL LOGIN authentication failed: x")
		if calls := smtpCalls(d); calls != 1 || len(d.smtpAuthTracker.authTrouble) != 0 {
			t.Fatalf("client text withheld a valid pair: calls=%d marks=%d", calls, len(d.smtpAuthTracker.authTrouble))
		}
	})
}

func FuzzSMTPAuthLogTime(f *testing.F) {
	f.Add("2026-10-31T20:00:00Z")
	f.Add("\nOct 31 20:00:00 mail postfix/smtpd[99]: warning: x")
	f.Add("")
	f.Fuzz(func(t *testing.T, clientText string) {
		now := time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)
		for _, prefix := range []string{now.Format(time.Stamp), now.Format(time.RFC3339Nano)} {
			line := prefix + " mail dovecot: auth: sql(" + clientText + ",203.0.113.95): unknown user"
			if at := smtpAuthLogTime(line, now); !at.Equal(now) {
				t.Fatalf("client text changed source timestamp to %s", at)
			}
		}
	})
}

// A client chooses its login name and the text smtpd echoes into rejects and
// warnings. Only the address in smtpd's queue record of an authenticated
// client is vouched for, and only when the record names a mailbox.
func FuzzPostfixSASLSuccessAddress(f *testing.F) {
	for _, s := range []string{"alice@example.net", "", "x, client=unknown[198.51.100.9], sasl_method=PLAIN", "x: client=unknown[198.51.100.9], sasl_method=PLAIN, sasl_username=y", "\npostfix/smtpd[9]: 4ABC: client=unknown[198.51.100.9], sasl_method=PLAIN, sasl_username=y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, clientText string) {
		d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
		feed(d, clock,
			"postfix/smtpd[9]: 4ABC123: client=unknown[203.0.113.7], sasl_method=PLAIN, sasl_username="+clientText,
			"postfix/smtpd[9]: warning: Illegal address syntax from unknown[198.51.100.9] in RCPT command: <"+clientText+">",
			"postfix/smtpd[9]: NOQUEUE: reject: RCPT from unknown[198.51.100.9]: 554 5.7.1 <"+clientText+">: Relay access denied; from=<"+clientText+"> to=<x@example.net> proto=ESMTP helo=<"+clientText+">",
			"postfix/smtpd[9]: 4ABC123: client=unknown[198.51.100.9], orig_client="+clientText)
		want := map[string]bool{}
		if _, user := postfixSASLSuccess("4ABC123: client=unknown[203.0.113.7], sasl_method=PLAIN, sasl_username=" + clientText); normalizeSprayMailbox(user) != "" {
			want["203.0.113.7"] = true
		}
		if got := smtpSuccessIPs(d); !maps.Equal(got, want) {
			t.Fatalf("client text %q changed successful logins to %v, want %v", clientText, got, want)
		}
		if calls := smtpCalls(d); calls != 0 {
			t.Fatalf("success lines counted %d failures", calls)
		}
	})
}

// The login name ends where smtpd's own trailing fields begin, whatever the
// rest of the line holds.
func FuzzPostfixSASLSuccessUser(f *testing.F) {
	for _, s := range []string{
		"4ABC123: client=unknown[203.0.113.5], sasl_method=PLAIN, sasl_username=alice@example.com",
		"4ABC123: client=unknown[203.0.113.5], sasl_method=PLAIN, sasl_username=a, sasl_sender=b, orig_queue_id=c, orig_client=d",
		"4ABC123: client=unknown[203.0.113.5], sasl_method=PLAIN, sasl_username=, sasl_sender=, sasl_username=x",
		"4ABC123: client=unknown[203.0.113.5], sasl_method=, sasl_username=\xff\xfe",
		"", ": client=", ", sasl_method=, sasl_username=",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		ip, user := postfixSASLSuccess(msg)
		if ip == "" && user != "" {
			t.Fatalf("refused line %q returned user %q", msg, user)
		}
		for _, field := range []string{", sasl_sender=", ", orig_queue_id=", ", orig_client="} {
			if strings.Contains(user, field) {
				t.Fatalf("user %q from %q holds %q", user, msg, field)
			}
		}
	})
}

func FuzzNormalizeSprayMailbox(f *testing.F) {
	for _, s := range []string{"", " User@Example.COM ", strings.Repeat("a", 253) + " B", strings.Repeat("\u20ac", 100), "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := normalizeSprayMailbox(input)
		if len(got) > maxSprayMailboxBytes || !utf8.ValidString(got) {
			t.Fatalf("key has %d bytes, valid UTF-8 = %v", len(got), utf8.ValidString(got))
		}
		if again := normalizeSprayMailbox(got); again != got {
			t.Fatalf("normalizing twice changed %q to %q", got, again)
		}
	})
}

func FuzzMailboxResolverResolve(f *testing.F) {
	for _, s := range []string{
		"", "@", "a@", "@example.com", "a/b", "exampleco", "__cpanel__service__auth__x",
		"info@example.com", "info@example.com.", "exampleco@example.com.",
		"inof@example.com", "exampelco@example.com", "in+fo@example.com",
		"info@exmaple.com", "inf@exampel.com.", "in+fo@exmaple.com", "exampelco@exmaple.com",
		"otherco@example.or", "nosuch@example.nt", "x@../../etc", "x@example.com\x00", "\xff@example.com",
		"info@shop1.example.org", "nosuch@shop1.example.org", "nosuch@dead1.example.org", "in+foo@shop.example.org",
		strings.Repeat("a", 300) + "@example.com",
		"nosuch@example.com" + strings.Repeat(" ", maxSprayMailboxBytes) + "suffix",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		src := newSiblingMailboxSource()
		owners := map[string]bool{}
		for _, owner := range src.snapshot.Domains {
			owners[owner] = true
		}
		name := normalizeSprayMailbox(input)
		got := newCPanelMailboxResolver(src, time.Now).Resolve(input)
		if got.name != normalizeSprayMailbox(got.name) {
			t.Fatalf("Resolve(%q) returned an invalid key %q", input, got.name)
		}
		if got.name != name {
			local, domain, _ := strings.Cut(got.name, "@")
			owner := src.snapshot.Domains[domain]
			listed := owner != "" && (local == owner || slices.Contains(src.lists[owner][domain], local))
			if got.exist != mailboxExists || !listed {
				t.Fatalf("Resolve(%q) = %+v, not a listed mailbox", name, got)
			}
		}
		for _, account := range src.mailboxCalls {
			if !owners[account] {
				t.Fatalf("Resolve(%q) read %q, not an owner", name, account)
			}
		}
	})
}

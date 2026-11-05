//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPath6_StartupRestoresFullWindow(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	root := t.TempDir()
	sub := filepath.Join(root, "a")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf("id-H\nusera 1 1\n<usera@host.example>\n0 0\n-local\n1\nv%d@outside.example\n\n070  X-PHP-Script: site-a.example/index.php for %s\n", i, path6IP)
		file := filepath.Join(sub, fmt.Sprintf("queued%d-H", i))
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-time.Duration(i+2) * time.Hour)
		if i == 4 {
			at = now.Add(-25 * time.Hour)
		}
		if err := os.Chtimes(file, at, at); err != nil {
			t.Fatal(err)
		}
	}
	runStartupSpoolWalker(root, p)
	requireNoPath6(t, *findings)
	if got := p.eng.form.count(formRelayKey(path6IP), now.Add(-24*time.Hour)); got != 4 {
		t.Fatalf("restored %d outside recipients, want 4 within the window", got)
	}
	feedScriptMail(t, p, "live", "a", path6Form, path6IP, now, "new@outside.example")
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("live mail did not use restored evidence: %+v", got)
	}
}

func TestPath6_SkippedMessageCannotTriggerFinding(t *testing.T) {
	for _, reason := range []string{"cron", "admin", "staff", "proxy", "infra", "cloudflare", "unknown-account", "own-recipient"} {
		t.Run(reason, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			p.SetRebuilding(true)
			feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
			p.SetRebuilding(false)
			site, script := "a", path6Form
			switch reason {
			case "cron":
				script = "/wp-cron.php"
			case "admin":
				script = "/wp-admin/post.php"
			case "staff":
				p.eng.form.markStaff("usera", formRelayKey(path6IP), path6T0)
			case "proxy":
				p.policies = newTestPoliciesWithProxy(t, path6IP+"/32")
				p.eng.SetPolicies(p.policies)
			case "infra":
				p.eng.config().InfraIPs = []string{path6IP}
			case "cloudflare":
				p.eng.SetCloudflareCover(func(string) bool { return true })
			case "unknown-account":
				site = "b"
			}
			recipient := "new@outside.example"
			if reason == "own-recipient" {
				recipient = "admin@site-a.example"
			}
			feedScriptMail(t, p, "skipped", site, script, path6IP, path6T0.Add(3*time.Hour), recipient)
			requireNoPath6(t, *findings)
		})
	}
}

func TestPath6_LaterScriptFiresDuringClientCooldown(t *testing.T) {
	p, findings := path6Pipeline(t, "a", "b")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	feedVictims(t, p, "b", "/contact.php", path6IP, 5, 2, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("client findings = %d, want 1", len(got))
	}
	got := path6Of(*findings, path6Script)
	if len(got) != 2 || got[0].ScriptKey != "site-a.example:"+path6Form || got[1].ScriptKey != "site-b.example:/contact.php" {
		t.Fatalf("script findings = %+v, want both abused forms", got)
	}
}

func TestPath6_PHPNamePrefixDoesNotExemptOtherScripts(t *testing.T) {
	for _, script := range []string{"/wp-cron.php5", "/wp-cron.phpmailer.php", "/contact.php5/wp-admin/post.php", "/contact.phtml/wp-cron.php"} {
		t.Run(script, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			feedVictims(t, p, "a", script, path6IP, 0, 5, path6T0)
			if got := path6Of(*findings, path6Check); len(got) != 1 {
				t.Fatalf("non-cron script exempted: %+v", got)
			}
		})
	}
}

func TestPath6_ExemptHistoryCannotTriggerAnotherAccount(t *testing.T) {
	for _, exemption := range []string{"ignored", "staff"} {
		t.Run(exemption, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a", "b")
			feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
			if exemption == "ignored" {
				p.ignores = newIgnoreList()
				p.ignores.Add("site-a.example:"+path6Form, time.Time{}, "test", "bulk sender")
			} else {
				feedScriptMail(t, p, "admin", "a", "/wp-admin/post.php", path6IP, path6T0.Add(2*time.Hour), "admin@site-a.example")
			}
			feedVictims(t, p, "b", path6Form, path6IP, 4, 1, path6T0)
			requireNoPath6(t, *findings)
			feedVictims(t, p, "b", path6Form, path6IP, 5, 4, path6T0)
			clients, scripts := path6Of(*findings, path6Check), path6Of(*findings, path6Script)
			if len(clients) != 1 || len(scripts) != 1 || scripts[0].ScriptKey != "site-b.example:"+path6Form {
				t.Fatalf("expected only the non-exempt account: %+v", *findings)
			}
			if strings.Contains(clients[0].Details, "site-a.example") {
				t.Fatalf("exempt script remains in the evidence: %s", clients[0].Details)
			}
		})
	}
}

func TestPath6_FindingsKeepEvidenceDuringSweep(t *testing.T) {
	emitted := 0
	for i := 0; i < 20000; i++ {
		eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), nil, path6Cfg(), nil)
		eng.form.record(formRelayKey(path6IP), path6IP, "usera", "site-a.example:/index.php", "m", path6T0.Add(-24*time.Hour),
			[]string{"a@outside.example", "b@outside.example", "c@outside.example", "d@outside.example", "e@outside.example"}, false, 24*time.Hour, 5)
		var wg sync.WaitGroup
		startSweep := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSweep
			eng.form.sweep(path6T0.Add(time.Minute), 24*time.Hour)
		}()
		if i != 0 {
			close(startSweep)
		}
		findings := eng.formRelayFindings("site-a.example:/index.php", path6IP, "usera", 5, 24*time.Hour, path6T0, nil)
		if i == 0 {
			// Guarantee a positive control even if expiry wins every race.
			close(startSweep)
		}
		wg.Wait()
		for _, f := range path6Of(findings, path6Check) {
			emitted++
			if !strings.Contains(f.Details, "site-a.example:/index.php (account usera): 5") ||
				!strings.Contains(f.Details, "Recipient domains: outside.example") {
				t.Fatalf("finding lost evidence during expiry: %+v", f)
			}
		}
	}
	if emitted == 0 {
		t.Fatal("no client findings checked")
	}
}

func TestPath6_ForwardedTextCannotChangeClient(t *testing.T) {
	for _, remote := range []string{path6IP, "2001:db8::9"} {
		t.Run(remote, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			for i, forwarded := range []string{"192.0.2.1", "unknown", "192.0.2.1, 198.51.100.1", "arbitrary for text", " for , for "} {
				feedScriptMail(t, p, fmt.Sprintf("forwarded%d", i), "a", path6Form, forwarded+", "+remote,
					path6T0.Add(time.Duration(i)*time.Minute), fmt.Sprintf("v%d@outside.example", i))
			}
			got := path6Of(*findings, path6Check)
			if len(got) != 1 || got[0].SourceIP != remote || got[0].ScriptKey != "site-a.example:"+path6Form {
				t.Fatalf("forwarded text changed attribution: %+v", got)
			}
			if len(p.eng.form.ips) != 1 {
				t.Fatalf("forwarded text split the client into %d entries", len(p.eng.form.ips))
			}
		})
	}
}

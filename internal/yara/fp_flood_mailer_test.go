//go:build yara

package yara

import "testing"

// Regression tests for the mailer-family arm of the 2026-07 FP-flood.
// Brand mailer rules fired on any file whose bytes contained the brand as a
// substring ("King Mailer" inside "Checking Mailer", "KingMailer" inside a
// "kingmailer_log" JSON key, "Anonymous Email" as a bbPress field label).
// mailer_smtp_relay fired on stock PHPMailer/CodeIgniter SMTP clients whose
// response-reading while(fgets($conn)) loop looked like a recipient loop.
// mailer_mass_sender fired on WP core pluggable.php (a mail() mention in a
// comment near an unrelated loop) and on backup archives. The fixes require
// a PHP open tag plus a real send action, and tie the loop to the recipient.

func TestFPFlood_MailerKing_CheckingMailerAndJson(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// wp-mail-smtp-vue.php translation strings: "Checking Mailer" contains the
	// brand as a substring but is not the King Mailer tool.
	trans := []byte(`<?php return array('Checking Mailer Configuration' => 'Checking Mailer Configuration');`)
	if hasYaraRule(s.ScanBytes(trans), "mailer_king") {
		t.Error("mailer_king FP: matched 'Checking Mailer' translation string")
	}
	// wp-optimize plugin catalog JSON: "kingmailer_log" field key, not PHP.
	pluginJSON := []byte(`{"plugins":["kingmailer_logging","wp-mail-smtp"],"count":2}`)
	if hasYaraRule(s.ScanBytes(pluginJSON), "mailer_king") {
		t.Error("mailer_king FP: matched a kingmailer_log JSON key")
	}
	pluginCode := []byte(`<?php $options['kingmailer_log']=true; mail($admin,'Plugin status',$body);`)
	if hasYaraRule(s.ScanBytes(pluginCode), "mailer_king") {
		t.Error("mailer_king FP: matched kingmailer_log key in PHP that sends unrelated mail")
	}
	mal := []byte(`<?php /* King Mailer v2 */ $to=$_POST['to']; mail($to, $_POST['s'], $_POST['b']);`)
	if !hasYaraRule(s.ScanBytes(mal), "mailer_king") {
		t.Error("mailer_king regression: real King Mailer script not detected")
	}
}

func TestFPFlood_MailerAnonemail_BbpressField(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// bbPress functions.php: the phrase "anonymous email" is a form field
	// label for guest posts, not the AnonEmail mailer tool.
	bb := []byte(`<?php // Filter and validate the anonymous email address for guest posts.
function bbp_filter_anonymous_post_data($r=array()){ $r['bbp_anonymous_email']=sanitize_email($r['bbp_anonymous_email']); return $r; }`)
	if hasYaraRule(s.ScanBytes(bb), "mailer_anonemail") {
		t.Error("mailer_anonemail FP: matched bbPress anonymous-email field handling")
	}
	for _, brand := range []string{"AnonEmail", "anon_email"} {
		mal := []byte(`<?php /* ` + brand + ` anonymous sender */ $to=$_POST['rcpt']; mail($to,'x',$_POST['msg']);`)
		if !hasYaraRule(s.ScanBytes(mal), "mailer_anonemail") {
			t.Errorf("mailer_anonemail regression: %s brand variant not detected", brand)
		}
	}
}

func TestFPFlood_MailerBrands_NonPhpExcluded(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A .pot / minified-JS style buffer naming the brands but not PHP.
	nonPhp := []byte(`msgid "Leaf Mailer status"\nmsgstr ""\n// InboxSender label, Alfa Mailer button`)
	for _, rule := range []string{"mailer_leafmailer", "mailer_inbox_sender", "mailer_alfa_sender"} {
		if hasYaraRule(s.ScanBytes(nonPhp), rule) {
			t.Errorf("%s FP: matched a non-PHP resource that only names the brand", rule)
		}
	}
	commentOnly := []byte(`<?php /* King Mailer documentation: call mail($to, $subject, $body) here. */`)
	if hasYaraRule(s.ScanBytes(commentOnly), "mailer_king") {
		t.Error("mailer_king FP: counted mail() inside a comment as a send action")
	}
	// Real branded mailers: brand + php + a send action.
	for _, tc := range []struct{ rule, body string }{
		{"mailer_leafmailer", `<?php /* Leaf PHPMailer */ $s=fsockopen($h,25); fputs($s,"MAIL FROM:<x>");`},
		{"mailer_inbox_sender", `<?php /* Inbox Sender */ foreach($l as $to){ mail($to,'s','b'); }`},
		{"mailer_inbox_sender", `<?php /* inbox_sender */ foreach($l as $to){ mail($to,'s','b'); }`},
		{"mailer_alfa_sender", `<?php /* Alfa Sender */ mail/* split */($_POST['to'],'s',$_POST['b']);`},
	} {
		if !hasYaraRule(s.ScanBytes([]byte(tc.body)), tc.rule) {
			t.Errorf("%s regression: real branded mailer not detected", tc.rule)
		}
	}
	for _, tc := range []struct{ rule, key string }{
		{"mailer_leafmailer", "leafmailer_log"},
		{"mailer_king", "kingmailer_log"},
		{"mailer_anonemail", "anonemail_enabled"},
		{"mailer_inbox_sender", "inboxsender_status"},
		{"mailer_alfa_sender", "alfasender_status"},
	} {
		body := []byte(`<?php $options['` + tc.key + `']=true; mail($admin,'Plugin status',$body);`)
		if hasYaraRule(s.ScanBytes(body), tc.rule) {
			t.Errorf("%s FP: matched embedded brand in %s key", tc.rule, tc.key)
		}
	}
}

func TestFPFlood_MailerSmtpRelay_StockClientResponseLoop(t *testing.T) {
	s := loadRepoYaraScanner(t)
	nonPHP := []byte(`fsockopen($host,25); foreach($recipients as $to){ fwrite($s,"MAIL FROM:<x> RCPT TO:<$to>"); }`)
	if hasYaraRule(s.ScanBytes(nonPHP), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: matched documentation without PHP source")
	}
	// Stock PHPMailer/CodeIgniter SMTP.php: fsockopen + "MAIL FROM:" plus a
	// while(fgets($conn)) loop that reads the server RESPONSE, not recipients.
	stock := []byte(`<?php
class SMTP {
	protected $smtp_conn;
	public function connect($host,$port=25){ $this->smtp_conn = fsockopen($host,$port); }
	public function mailSend($from){ $this->client_send('MAIL FROM:<'.$from.">\r\n"); return $this->getLines(); }
	protected function getLines(){ $data=''; while($str = @fgets($this->smtp_conn, 515)){ $data.=$str; if(substr($str,3,1)==' ')break; } return $data; }
}
`)
	if hasYaraRule(s.ScanBytes(stock), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: matched a stock SMTP client's response-reading loop")
	}
	unrelatedRecipientLoop := []byte(`<?php
class SMTP {
	public function connect($host){ $this->conn=fsockopen($host,25); }
	public function sender($from){ fwrite($this->conn,"MAIL FROM:<$from>\r\n"); }
	public function normalize($recipients){ foreach($recipients as $to){ $clean[]=trim($to); } return $clean; }
}`)
	if hasYaraRule(s.ScanBytes(unrelatedRecipientLoop), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: joined an unrelated recipient-normalization loop to SMTP commands")
	}
	// Real mass relay: iterates a recipient list and sends to each.
	mal := []byte(`<?php $list=file('targets.txt'); foreach($list as $to){ $sk=fsockopen('127.0.0.1',25); fputs($sk,"MAIL FROM:<spam@x>\r\nRCPT TO:<$to>\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(mal), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: real mass SMTP relay not detected")
	}
	genericReader := []byte(`<?php $s=fsockopen('127.0.0.1',25); $fp=fopen('targets.txt','r'); while($e=fgets($fp)){ fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$e>\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(genericReader), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: recipient file loop with generic variable names not detected")
	}
	nestedGuard := []byte(`<?php $s=fsockopen('127.0.0.1',25); $fp=fopen('targets.txt','r'); while($e=fgets($fp)){ if(!$e){ continue; } fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$e>\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(nestedGuard), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: recipient loop with a nested validation block not detected")
	}
	obfuscatedCall := []byte(`<?php $s=fsockopen/* split */('127.0.0.1',25); foreach($recipients as $to){ fputs($s,"MAIL FROM :<x>\r\nRCPT TO:<$to>\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(obfuscatedCall), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: comment-obfuscated socket call not detected")
	}
}

func TestFPFlood_MailerMassSender_CoreAndBackup(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// WP core pluggable.php shape: a mail() mention in a comment, an unrelated
	// foreach over $users, and $emails built elsewhere - no per-recipient send.
	core := []byte(`<?php
function wp_notify_moderator($comment_id){
	$emails = array(get_option('admin_email'));
	foreach ((array)$emails as $email){ $email = trim($email); }
	// Set to use PHP's mail() when SMTP is unavailable.
	return true;
}
`)
	if hasYaraRule(s.ScanBytes(core), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: matched WP core notify function (comment mail(), unrelated loop)")
	}
	// A backup plugin that emails one report via a single mail() call.
	report := []byte(`<?php $addrs=explode(',', $opts['email']); $emails=$addrs; mail("admin@site", "Backup done", $summary);`)
	if hasYaraRule(s.ScanBytes(report), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: matched a single-shot backup-report mail()")
	}
	outsideLoop := []byte(`<?php foreach($emails as $email){ $email=trim($email); } mail($admin,'Summary',$body);`)
	if hasYaraRule(s.ScanBytes(outsideLoop), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: joined a closed recipient loop to a later single-shot mail")
	}
	commentOnly := []byte(`<?php while($line=fgets($log)){ // mail($line,'subject','body') would notify the owner.
		process($line); }`)
	if hasYaraRule(s.ScanBytes(commentOnly), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: counted mail() inside a loop comment as a send action")
	}
	// Real mass sender: recipient loop sends to each list entry.
	for _, mal := range [][]byte{
		[]byte(`<?php $fh=fopen('list.txt','r'); while($e=fgets($fh)){ mail($e,'Win','http://evil/'); }`),
		[]byte(`<?php while($e=fgets($fh)){mail($e,'Win','http://evil/');}`),
		[]byte(`<?php foreach($_POST['recipients'] as $to){ mail($to, $_POST['subj'], $_POST['body']); }`),
		[]byte(`<?php for($i=0;$i<count($emails);$i++){ mail($emails[$i],'Win','http://evil/'); }`),
		[]byte(`<?php foreach($emails as $email){ if(!$email){ continue; } mail($email,'Win','http://evil/'); }`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "mailer_mass_sender") {
			t.Errorf("mailer_mass_sender regression: real recipient-loop mailer not detected: %s", mal)
		}
	}
}

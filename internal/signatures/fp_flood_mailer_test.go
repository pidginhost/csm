package signatures

import "testing"

// YAML-engine mirror of the mailer-family FP-flood fix. The YAML engine only
// scans .php, so the .php false positives are: bbPress functions.php (the
// phrase "Anonymous Email"), stock PHPMailer SMTP.php (fsockopen + MAIL FROM
// + a response-reading loop), and wp-mail-smtp translation code.

func TestFPFlood_YML_MailerAnonemail_BbpressField(t *testing.T) {
	s := loadRepoScanner(t)
	bb := []byte(`<?php // Validate the anonymous email address for guest posts.
function bbp_filter_anonymous_post_data($r=array()){ $r['bbp_anonymous_email']=sanitize_email($r['bbp_anonymous_email']); return $r; }`)
	if hasRule(s.ScanContent(bb, ".php"), "mailer_anonemail") {
		t.Error("mailer_anonemail FP: matched bbPress anonymous-email field label")
	}
	for _, brand := range []string{"AnonEmail", "anon_email"} {
		mal := []byte(`<?php /* ` + brand + ` */ $to=$_POST['rcpt']; mail($to,'x',$_POST['m']);`)
		if !hasRule(s.ScanContent(mal, ".php"), "mailer_anonemail") {
			t.Errorf("mailer_anonemail regression: %s brand variant not detected", brand)
		}
	}
}

func TestFPFlood_YML_MailerSmtpRelay_StockClient(t *testing.T) {
	s := loadRepoScanner(t)
	nonPHP := []byte(`fsockopen($host,25); foreach($recipients as $to){ fwrite($s,"MAIL FROM:<x> RCPT TO:<$to>"); }`)
	if hasRule(s.ScanContent(nonPHP, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: matched documentation without PHP source")
	}
	stock := []byte(`<?php
class SMTP {
	protected $smtp_conn;
	public function connect($host,$port=25){ $this->smtp_conn=fsockopen($host,$port); }
	public function mailSend($from){ fwrite($this->smtp_conn,'MAIL FROM:<'.$from.">\r\n"); return $this->getLines(); }
	protected function getLines(){ $d=''; while($str=@fgets($this->smtp_conn,515)){ $d.=$str; } return $d; }
}`)
	if hasRule(s.ScanContent(stock, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: matched a stock SMTP client library")
	}
	unrelatedRecipientLoop := []byte(`<?php
class SMTP {
	public function connect($host){ $this->conn=fsockopen($host,25); }
	public function sender($from){ fwrite($this->conn,"MAIL FROM:<$from>\r\n"); }
	public function normalize($recipients){ foreach($recipients as $to){ $clean[]=trim($to); } return $clean; }
}`)
	if hasRule(s.ScanContent(unrelatedRecipientLoop, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: joined an unrelated recipient-normalization loop to SMTP commands")
	}
	mal := []byte(`<?php $list=file('t.txt'); foreach($list as $to){ $s=fsockopen('127.0.0.1',25); fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$to>\r\n"); }`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: real mass relay not detected")
	}
	genericReader := []byte(`<?php $s=fsockopen('127.0.0.1',25); $fp=fopen('targets.txt','r'); while($e=fgets($fp)){ fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$e>\r\n"); }`)
	if !hasRule(s.ScanContent(genericReader, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: recipient file loop with generic variable names not detected")
	}
	nestedGuard := []byte(`<?php $s=fsockopen('127.0.0.1',25); $fp=fopen('targets.txt','r'); while($e=fgets($fp)){ if(!$e){ continue; } fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$e>\r\n"); }`)
	if !hasRule(s.ScanContent(nestedGuard, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: recipient loop with a nested validation block not detected")
	}
}

func TestFPFlood_YML_MailerSmtpRelay_AlternateInputs(t *testing.T) {
	s := loadRepoScanner(t)
	for _, body := range [][]byte{
		[]byte(`<?php $s=fsockopen('127.0.0.1',25); for($i=0;$i<count($emails);$i++){ fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<".$emails[$i].">\r\n"); }`),
		[]byte(`<?php $h=$_POST['host']; $f=$_POST['from']; $t=$_POST['to']; $s=fsockopen($h,25); fputs($s,"MAIL FROM:<$f>\r\n"); fwrite($s,"RCPT TO:<$t>\r\n");`),
		[]byte(`<?php $s=fsockopen/* split */('127.0.0.1',25); foreach($recipients as $to){ fputs($s,"MAIL FROM :<x>\r\nRCPT TO:<$to>\r\n"); }`),
	} {
		if !hasRule(s.ScanContent(body, ".php"), "mailer_smtp_relay") {
			t.Errorf("mailer_smtp_relay regression: YARA-detected relay shape missed by YAML engine: %s", body)
		}
	}
}

func TestFPFlood_YML_MailerKing_CheckingMailer(t *testing.T) {
	s := loadRepoScanner(t)
	trans := []byte(`<?php return array('Checking Mailer Configuration'=>'Checking Mailer Configuration');`)
	if hasRule(s.ScanContent(trans, ".php"), "mailer_king") {
		t.Error("mailer_king FP: matched 'Checking Mailer' translation string")
	}
	pluginCode := []byte(`<?php $options['kingmailer_log']=true; mail($admin,'Plugin status',$body);`)
	if hasRule(s.ScanContent(pluginCode, ".php"), "mailer_king") {
		t.Error("mailer_king FP: matched kingmailer_log key in PHP that sends unrelated mail")
	}
	mal := []byte(`<?php /* King Mailer */ $to=$_POST['to']; mail($to,$_POST['s'],$_POST['b']);`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_king") {
		t.Error("mailer_king regression: real King Mailer script not detected")
	}
}

func TestFPFlood_YML_MailerBrandCommentObfuscatedSink(t *testing.T) {
	s := loadRepoScanner(t)
	commentOnly := []byte(`<?php /* King Mailer documentation: call mail($to, $subject, $body) here. */`)
	if hasRule(s.ScanContent(commentOnly, ".php"), "mailer_king") {
		t.Error("mailer_king FP: counted mail() inside a comment as a send action")
	}
	for _, tc := range []struct{ rule, body string }{
		{"mailer_alfa_sender", `<?php /* Alfa Sender */ mail/* split */($to,'s','b');`},
		{"mailer_inbox_sender", `<?php /* inbox_sender */ mail($to,'s','b');`},
	} {
		if !hasRule(s.ScanContent([]byte(tc.body), ".php"), tc.rule) {
			t.Errorf("%s regression: branded mailer variant not detected", tc.rule)
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
		if hasRule(s.ScanContent(body, ".php"), tc.rule) {
			t.Errorf("%s FP: matched embedded brand in %s key", tc.rule, tc.key)
		}
	}
}

func TestFPFlood_YML_MailerMassSender_CoreNotify(t *testing.T) {
	s := loadRepoScanner(t)
	core := []byte(`<?php
function wp_notify_moderator($id){
	$emails = array(get_option('admin_email'));
	foreach ((array)$emails as $email){ $email = trim($email); }
	// Set to use PHP's mail() when SMTP is unavailable.
	return true;
}`)
	if hasRule(s.ScanContent(core, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: matched WP core notify function")
	}
	outsideLoop := []byte(`<?php foreach($emails as $email){ $email=trim($email); } mail($admin,'Summary',$body);`)
	if hasRule(s.ScanContent(outsideLoop, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: joined a closed recipient loop to a later single-shot mail")
	}
	commentOnly := []byte(`<?php while($line=fgets($log)){ // mail($line,'subject','body') would notify the owner.
		process($line); }`)
	if hasRule(s.ScanContent(commentOnly, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender FP: counted mail() inside a loop comment as a send action")
	}
	mal := []byte(`<?php $fh=fopen('list.txt','r'); while($e=fgets($fh)){ mail($e,'Win','http://evil/'); }`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: real recipient-loop mailer not detected")
	}
	forLoop := []byte(`<?php for($i=0;$i<count($emails);$i++){ mail($emails[$i],'Win','http://evil/'); }`)
	if !hasRule(s.ScanContent(forLoop, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: indexed recipient for-loop not detected")
	}
	minified := []byte(`<?php while($e=fgets($fh)){mail($e,'Win','http://evil/');}`)
	if !hasRule(s.ScanContent(minified, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: minified recipient loop not detected")
	}
	nestedGuard := []byte(`<?php foreach($emails as $email){ if(!$email){ continue; } mail($email,'Win','http://evil/'); }`)
	if !hasRule(s.ScanContent(nestedGuard, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: recipient loop with a nested validation block not detected")
	}
}

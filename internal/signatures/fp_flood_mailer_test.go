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
	mal := []byte(`<?php /* AnonEmail */ $to=$_POST['rcpt']; mail($to,'x',$_POST['m']);`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_anonemail") {
		t.Error("mailer_anonemail regression: real AnonEmail tool not detected")
	}
}

func TestFPFlood_YML_MailerSmtpRelay_StockClient(t *testing.T) {
	s := loadRepoScanner(t)
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
	mal := []byte(`<?php $list=file('t.txt'); foreach($list as $to){ $s=fsockopen('127.0.0.1',25); fputs($s,"MAIL FROM:<x>\r\nRCPT TO:<$to>\r\n"); }`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: real mass relay not detected")
	}
}

func TestFPFlood_YML_MailerKing_CheckingMailer(t *testing.T) {
	s := loadRepoScanner(t)
	trans := []byte(`<?php return array('Checking Mailer Configuration'=>'Checking Mailer Configuration');`)
	if hasRule(s.ScanContent(trans, ".php"), "mailer_king") {
		t.Error("mailer_king FP: matched 'Checking Mailer' translation string")
	}
	mal := []byte(`<?php /* King Mailer */ $to=$_POST['to']; mail($to,$_POST['s'],$_POST['b']);`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_king") {
		t.Error("mailer_king regression: real King Mailer script not detected")
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
	mal := []byte(`<?php $fh=fopen('list.txt','r'); while($e=fgets($fh)){ mail($e,'Win','http://evil/'); }`)
	if !hasRule(s.ScanContent(mal, ".php"), "mailer_mass_sender") {
		t.Error("mailer_mass_sender regression: real recipient-loop mailer not detected")
	}
}

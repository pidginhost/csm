package antispam

import (
	"strconv"
	"strings"
)

// Marker lines bracket every block CSM writes into a shared Exim file.
const (
	MarkerBegin = "# CSM-ANTISPAM BEGIN"
	MarkerEnd   = "# CSM-ANTISPAM END"
)

// EximHooks is the rendered Exim side of the integration.
type EximHooks struct {
	// RCPT is ACL_SPAM_SCAN_CHECK_BLOCK/custom_begin_spam_scan_check.
	RCPT string
	// Scan is ACL_SPAM_SCAN_BLOCK/custom_begin_spam_scan.
	Scan string
	// Post is ACL_CHECK_MESSAGE_POST_BLOCK/custom_begin_check_message_post.
	Post string
	// Config is the block CSM inserts after @CONFIG@ in /etc/exim.conf.local.
	Config string
}

// eligible skips authenticated sessions and the peers cPanel exempts from
// its own spam scan (spec section 5.1).
const eligible = "  !authenticated = *\n" +
	"  !hosts = <; 127.0.0.0/8 ; ::1 ; +trustedmailhosts ; +cpanel_mail_netblocks\n"

// optIn resolves the recipient's account with cPanel's own owner rule and
// reads its native Spam Filters toggle. A missing owner or home is "off".
const optIn = "${if exists{/etc/global_spamassassin_enable}{on}" +
	"{${lookup passwd{${if eq{$domain}{$primary_hostname}{${sg{$local_part}{\\N[/+].*\\N}{}}}" +
	"{${lookup{$domain}lsearch{/etc/userdomains}}}}}" +
	"{${if exists{${extract{5}{:}{$value}}/.spamassassinenable}{on}{off}}}{off}}}}"

const hasPolicy = "  condition = ${if or{{eq{$acl_m_csm_policy}{on}}{eq{$acl_m_csm_policy}{off}}}}\n"

const differs = "  condition = ${if and{{!eq{$acl_m_csm_rcpt}{}}{>{$recipients_count}{0}}{!eq{$acl_m_csm_rcpt}{$acl_m_csm_policy}}}}\n"

// RenderExim renders the three ACL hooks and the scanner address. Only
// validated integers and the validated socket path enter the text.
func RenderExim(s Settings) (EximHooks, error) {
	if err := s.Validate(); err != nil {
		return EximHooks{}, err
	}
	return EximHooks{
		RCPT:   renderRCPT(s.DryRun),
		Scan:   renderScan(s),
		Post:   renderPost(s),
		Config: MarkerBegin + "\nspamd_address = " + s.Socket + " variant=rspamd tmo=30s\n" + MarkerEnd + "\n",
	}, nil
}

func renderRCPT(dryRun bool) string {
	var b strings.Builder
	b.WriteString(MarkerBegin + "\n")
	b.WriteString("warn\n  set acl_m_csm_rcpt =\n\n")
	b.WriteString("warn\n" + eligible + "  set acl_m_csm_rcpt = skip\n\n")
	b.WriteString("warn\n  condition = ${if eq{$acl_m_csm_rcpt}{skip}}\n  domains = +local_domains\n" +
		"  set acl_m_csm_rcpt = " + optIn + "\n\n")
	b.WriteString("warn\n  condition = ${if and{{!eq{$acl_m_csm_rcpt}{}}{=={$recipients_count}{0}}}}\n" +
		"  set acl_m_csm_policy = $acl_m_csm_rcpt\n\n")
	if dryRun {
		b.WriteString("warn\n" + differs +
			"  logwrite = :main: CSM-ANTISPAM event=split mode=dry-run policy=$acl_m_csm_policy rcpt_class=$acl_m_csm_rcpt\n")
	} else {
		b.WriteString("defer\n" + differs +
			"  message = 452 4.5.3 Different spam policy, retry this recipient separately\n")
	}
	b.WriteString(MarkerEnd + "\n")
	return b.String()
}

func renderScan(s Settings) string {
	mode := "enforce"
	if s.DryRun {
		mode = "dry-run"
	}
	reject, tag := strconv.Itoa(s.RejectScore*10), strconv.Itoa(s.TagScore*10)
	var b strings.Builder
	b.WriteString(MarkerBegin + "\n")
	b.WriteString("warn\n  set acl_m_csm_scan_ok = 0\n  set acl_m_csm_score = 0\n\n")
	if !s.DryRun {
		b.WriteString("warn\n" + eligible + hasPolicy + "  remove_header = ^(?i)x-(spam|rspamd|spamd)-\n\n")
	}
	b.WriteString("warn\n" + eligible + hasPolicy + "  spam = nobody:true/defer_ok\n" +
		"  set acl_m_csm_scan_ok = 1\n  set acl_m_csm_score = $spam_score_int\n\n")
	b.WriteString("warn\n" + eligible + hasPolicy +
		"  logwrite = :main: CSM-ANTISPAM event=scan mode=" + mode + " policy=$acl_m_csm_policy " +
		"${if eq{$acl_m_csm_scan_ok}{1}{result=ok score=$acl_m_csm_score action=\"${sg{$spam_action}{[^a-z ]}{_}}\" " +
		"decision=${if eq{$acl_m_csm_policy}{off}{unfiltered}{${if >={$acl_m_csm_score}{" + reject + "}{reject}" +
		"{${if >={$acl_m_csm_score}{" + tag + "}{tag}{none}}}}}}}" +
		"{result=error score=none action=\"unavailable\" decision=none}}\n")
	b.WriteString(MarkerEnd + "\n")
	return b.String()
}

func renderPost(s Settings) string {
	if s.DryRun {
		return MarkerBegin + "\n" + MarkerEnd + "\n"
	}
	reject, tag := strconv.Itoa(s.RejectScore*10), strconv.Itoa(s.TagScore*10)
	return MarkerBegin + "\n" +
		"deny\n" + eligible +
		"  condition = ${if and{{eq{$acl_m_csm_policy}{on}}{eq{$acl_m_csm_scan_ok}{1}}{>={$acl_m_csm_score}{" + reject + "}}}}\n" +
		"  message = 550 5.7.1 Message rejected as spam\n\n" +
		"warn\n" + eligible +
		"  condition = ${if and{{eq{$acl_m_csm_policy}{on}}{eq{$acl_m_csm_scan_ok}{1}}{>={$acl_m_csm_score}{" + tag + "}}}}\n" +
		"  add_header = X-Spam-Status: Yes, score=${eval:$acl_m_csm_score/10}.${eval:$acl_m_csm_score%10}\n" +
		MarkerEnd + "\n"
}

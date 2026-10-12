package antispam

import (
	"strings"
	"testing"
)

func renderedHooks(t *testing.T, s Settings) EximHooks {
	t.Helper()
	h, err := RenderExim(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// rebuiltConf is a cut-down cPanel exim.conf with the hooks inlined where
// buildeximconf puts them.
func rebuiltConf(config, rcpt, scan, post string) string {
	return "primary_hostname = mail.example.test\n" + config +
		"begin acl\n" +
		"acl_smtp_rcpt:\n" + rcpt + "  accept\n\n" +
		"acl_smtp_data:\n" + scan + "  warn\n    log_message = between\n" + post + "  accept\n"
}

func enforceSettings() Settings {
	return Settings{Socket: DefaultSocket, RejectScore: DefaultRejectScore, TagScore: DefaultTagScore}
}

func TestCheckGeneratedAcceptsRenderedHooks(t *testing.T) {
	for _, dry := range []bool{false, true} {
		s := enforceSettings()
		s.DryRun = dry
		h := renderedHooks(t, s)
		conf := rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
		if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); err != nil {
			t.Errorf("dry run %t: %v", dry, err)
		}
	}
}

func TestCheckGeneratedRejectsDrift(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	stale := enforceSettings()
	stale.RejectScore = 20
	old := renderedHooks(t, stale)
	otherSocket := enforceSettings()
	otherSocket.Socket = "/run/rspamd/other.sock"
	moved := renderedHooks(t, otherSocket)
	dry := enforceSettings()
	dry.DryRun = true
	dryRun := renderedHooks(t, dry)
	for name, conf := range map[string]string{
		"post hook missing":     rebuiltConf(h.Config, h.RCPT, h.Scan, ""),
		"stale post threshold":  rebuiltConf(h.Config, h.RCPT, h.Scan, old.Post),
		"scan and post swapped": rebuiltConf(h.Config, h.RCPT, h.Post, h.Scan),
		"edited rcpt hook":      rebuiltConf(h.Config, strings.Replace(h.RCPT, "452", "451", 1), h.Scan, h.Post),
		"stale scanner address": rebuiltConf(moved.Config, h.RCPT, h.Scan, h.Post),
		"dry-run hooks left":    rebuiltConf(h.Config, dryRun.RCPT, dryRun.Scan, dryRun.Post),
		"unpaired marker":       rebuiltConf(h.Config, h.RCPT, h.Scan, MarkerBegin+"\n"),
	} {
		if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "spamd_address =") || strings.Contains(err.Error(), "acl_m_csm") {
			t.Errorf("%s: error repeats configuration text: %v", name, err)
		}
	}
}

func TestCheckGeneratedRejectsBadACLNames(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	conf := rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
	for _, names := range [][2]string{{"", "acl_smtp_data"}, {"acl_smtp_rcpt", ""}, {"acl_smtp_data", "acl_smtp_data"}} {
		if err := CheckGenerated(conf, h, names[0], names[1]); err == nil {
			t.Errorf("ACL names %q accepted", names)
		}
	}
}

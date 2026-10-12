package antispam

import (
	"errors"
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

func TestCheckGeneratedRejectsConditionalHooks(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	conditional := func(block string) string {
		return ".ifdef CSM_DISABLED_HOOK\n" + block + ".endif\n"
	}
	for name, conf := range map[string]string{
		"scanner": rebuiltConf(conditional(h.Config), h.RCPT, h.Scan, h.Post),
		"rcpt":    rebuiltConf(h.Config, conditional(h.RCPT), h.Scan, h.Post),
		"scan":    rebuiltConf(h.Config, h.RCPT, conditional(h.Scan), h.Post),
		"post":    rebuiltConf(h.Config, h.RCPT, h.Scan, conditional(h.Post)),
		"ACL section": strings.Replace(rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
			"begin acl\n", conditional("begin acl\n"), 1),
		"rcpt ACL": strings.Replace(rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
			"acl_smtp_rcpt:\n", conditional("acl_smtp_rcpt:\n"), 1),
		"data ACL": strings.Replace(rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
			"acl_smtp_data:\n", conditional("acl_smtp_data:\n"), 1),
		"macro directive": "SKIP_CSM = .ifndef CSM_DISABLED_HOOK\n" +
			rebuiltConf(h.Config, h.RCPT, "SKIP_CSM\n"+h.Scan+".else\n"+h.Post+".endif\n", ""),
		"physical directive": "hosts_lookup = example.invalid \\\n.ifdef CSM_DISABLED_HOOK\n" +
			rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post) + ".endif\n",
		"physical macro directive": "SKIP_CSM = .ifndef CSM_DISABLED_HOOK\nEND_SKIP = .endif\n" +
			"hosts_lookup = example.invalid \\\nSKIP_CSM\n" +
			rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post) + "END_SKIP\n",
	} {
		t.Run(name, func(t *testing.T) {
			blocks, err := LocateBlocks(conf)
			if err != nil {
				t.Fatalf("cannot identify owned blocks for removal: %v", err)
			}
			if err := CheckPlacement(blocks, "acl_smtp_rcpt", "acl_smtp_data"); err != nil {
				t.Fatalf("fixture has incorrect physical placement: %v", err)
			}
			if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); !errors.Is(err, ErrUnverifiable) {
				t.Fatalf("conditional hooks: got %v, want ErrUnverifiable", err)
			}
		})
	}
}

func TestCheckGeneratedAcceptsUnrelatedPreprocessing(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	for name, conf := range map[string]string{
		"unrelated macro":        "UNRELATED_OPTION = yes\n" + rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
		"unchanged substitution": "Yes = Yes\n" + rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
		"unrelated conditional": ".ifdef OPTIONAL_SETTING\nqueue_only\n.endif\n" +
			rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
		"macro ACL names": "RCPT_NAME = acl_smtp_rcpt:\nDATA_NAME = acl_smtp_data:\n" +
			strings.ReplaceAll(strings.ReplaceAll(rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
				"acl_smtp_rcpt:", "RCPT_NAME"), "acl_smtp_data:", "DATA_NAME"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckGeneratedRejectsMacroAlteredHooks(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	for _, macro := range []string{"Yes = No\n", "N = x\n", "CSM = OTHER\n"} {
		t.Run(strings.TrimSpace(macro), func(t *testing.T) {
			conf := macro + rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
			if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); err == nil {
				t.Fatal("accepted a macro that changes a rendered hook")
			}
		})
	}
	s := enforceSettings()
	s.Socket = "/run/rspamd/CSM.sock"
	h = renderedHooks(t, s)
	conf := "CSM = OTHER\n" + rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
	if err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data"); err == nil {
		t.Fatal("accepted a macro that changes the scanner address")
	}
}

func TestCheckGeneratedPlacementErrorOmitsConfiguration(t *testing.T) {
	h := renderedHooks(t, enforceSettings())
	const canary = "UNEXPECTED_ACL_CANARY"
	conf := strings.Replace(rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post),
		"acl_smtp_data:\n", canary+":\n", 1)
	err := CheckGenerated(conf, h, "acl_smtp_rcpt", "acl_smtp_data")
	if err == nil {
		t.Fatal("accepted a hook in an unexpected ACL")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error repeats configuration text: %v", err)
	}
}

package mcp

import (
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// PlatformFacts is what csm_overview reports about the host.
func PlatformFacts(info platform.Info) map[string]any {
	return map[string]any{
		"os":         string(info.OS),
		"os_version": info.OSVersion,
		"panel":      string(info.Panel),
		"web_server": string(info.WebServer),
		"mta":        string(platform.DetectMTA()),
	}
}

// ConfigSummary returns the non-secret configuration facts a support agent
// needs. It names each field it reads; it never walks the config struct, so
// a secret added to the configuration later cannot leak through it.
func ConfigSummary(cfg *config.Config, info platform.Info) map[string]any {
	fw := map[string]any{"enabled": false}
	if cfg.Firewall != nil {
		fw = map[string]any{
			"enabled":        cfg.Firewall.Enabled,
			"ipv6":           cfg.Firewall.IPv6,
			"tcp_in":         ints(cfg.Firewall.TCPIn),
			"udp_in":         ints(cfg.Firewall.UDPIn),
			"restricted_tcp": ints(cfg.Firewall.RestrictedTCP),
		}
	}
	t := cfg.Thresholds
	return map[string]any{
		"hostname":     cfg.Hostname,
		"mode":         cfg.Mode,
		"observe_mode": cfg.ObserveMode(),
		"state_path":   cfg.StatePath,
		"platform":     PlatformFacts(info),
		"listeners": map[string]any{
			"webui": cfg.WebUI.Listen,
			"mcp":   cfg.MCP.Listen,
		},
		"infra_ips":       strs(cfg.InfraIPs),
		"account_roots":   strs(cfg.AccountRoots),
		"disabled_checks": strs(cfg.DisabledChecks),
		"mail_logs":       map[string]any{"source": cfg.MailLogs.Source},
		"firewall":        fw,
		"auto_response": map[string]any{
			"enabled":             cfg.AutoResponse.Enabled,
			"dry_run":             cfg.AutoResponseDryRunEnabled(),
			"block_expiry":        cfg.AutoResponse.BlockExpiry,
			"max_blocks_per_hour": cfg.AutoResponse.MaxBlocksPerHour,
		},
		"protections": map[string]any{
			"bpf_enforcement":  cfg.BPFEnforcement.Enabled,
			"challenge_pages":  cfg.Challenge.Enabled,
			"php_shield":       cfg.PHPShield.Enabled,
			"email_av":         cfg.EmailAV.Enabled,
			"forward_guard":    cfg.EmailProtection.ForwardGuard.Enabled,
			"antispam":         cfg.EmailProtection.Antispam.Enabled,
			"antispam_dry_run": cfg.EmailProtection.Antispam.DryRun,
			"cloudflare":       cfg.Cloudflare.Enabled,
			"retention_sweeps": cfg.Retention.Enabled,
		},
		"signatures": map[string]any{
			"rules_dir":   cfg.Signatures.RulesDir,
			"auto_update": cfg.Signatures.AutoUpdate,
		},
		"thresholds": map[string]any{
			"smtp_bruteforce_threshold":        t.SMTPBruteForceThreshold,
			"smtp_bruteforce_window_min":       t.SMTPBruteForceWindowMin,
			"smtp_bruteforce_subnet_threshold": t.SMTPBruteForceSubnetThresh,
			"mail_bruteforce_threshold":        t.MailBruteForceThreshold,
			"mail_bruteforce_window_min":       t.MailBruteForceWindowMin,
			"mail_bruteforce_subnet_threshold": t.MailBruteForceSubnetThresh,
			"pam_bruteforce_threshold":         t.PAMBruteforceThreshold,
			"pam_bruteforce_window_min":        t.PAMBruteforceWindowMin,
			"multi_ip_login_threshold":         t.MultiIPLoginThreshold,
			"cred_stuffing_distinct_accounts":  t.CredStuffingDistinctAccounts,
			"mail_queue_warn":                  t.MailQueueWarn,
			"mail_queue_crit":                  t.MailQueueCrit,
			"deep_scan_interval_min":           t.DeepScanIntervalMin,
		},
	}
}

func ints(v []int) []int {
	if v == nil {
		return []int{}
	}
	return append([]int(nil), v...)
}

func strs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return append([]string(nil), v...)
}

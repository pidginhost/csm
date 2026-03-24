package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// Known safe kernel modules on cPanel/CloudLinux servers
var safeModules = map[string]bool{
	"kcare": true, "netconsole": true, "msdos": true, "dm_mod": true,
	"overlay": true, "fuse": true, "binfmt_misc": true,
	"nft_reject_inet": true, "xt_nat": true, "xt_comment": true,
	"xt_set": true, "xt_NFLOG": true, "xt_helper": true, "xt_CT": true,
	"xt_owner": true, "xt_conntrack": true, "xt_multiport": true,
	"xt_recent": true, "xt_limit": true, "xt_LOG": true,
	"ip_set": true, "ip_set_bitmap_port": true, "ip_set_list_set": true,
	"ip_set_hash_net": true, "ip_set_hash_ip": true,
	"nf_conntrack": true, "nf_nat": true, "nf_tables": true,
	"nft_chain_nat": true, "nft_compat": true, "nft_counter": true,
	"nf_log_syslog": true, "nf_reject_ipv4": true, "nf_reject_ipv6": true,
	"ip6_tables": true, "ip_tables": true, "iptable_filter": true,
	"iptable_nat": true, "iptable_raw": true, "iptable_mangle": true,
	"ip6table_filter": true, "ip6table_nat": true, "ip6table_raw": true,
	"ip6table_mangle": true,
	"bridge":          true, "stp": true, "llc": true, "bonding": true,
	"8021q": true, "vlan": true, "tun": true, "veth": true,
	"xfs": true, "ext4": true, "jbd2": true, "mbcache": true,
	"raid456": true, "raid1": true, "raid0": true, "md_mod": true,
	"async_raid6_recov": true, "async_memcpy": true, "async_pq": true,
	"async_xor": true, "async_tx": true, "raid6_pq": true,
	"sd_mod": true, "sg": true, "ahci": true, "libahci": true,
	"libata": true, "megaraid_sas": true, "mpt3sas": true,
	"scsi_transport_sas": true, "ses": true, "enclosure": true,
	"e1000e": true, "igb": true, "ixgbe": true, "i40e": true,
	"mlx4_en": true, "mlx4_core": true, "mlx5_core": true,
	"virtio_net": true, "virtio_blk": true, "virtio_scsi": true,
	"virtio_pci": true, "virtio_ring": true, "virtio": true,
	"sunrpc": true, "nfs": true, "nfsd": true, "lockd": true,
	"x86_pkg_temp_thermal": true, "coretemp": true, "crc32_pclmul": true,
	"ghash_clmulni_intel": true, "aesni_intel": true, "crypto_simd": true,
	"cryptd": true, "pcspkr": true, "i2c_i801": true, "i2c_core": true,
	"ipmi_si": true, "ipmi_devintf": true, "ipmi_msghandler": true,
	"lpc_ich": true, "mei_me": true, "mei": true, "wmi": true,
	"acpi_ipmi": true, "acpi_power_meter": true,
}

// CheckKernelModules compares loaded kernel modules against a baseline.
// New/unknown modules could indicate a rootkit.
func CheckKernelModules(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	modules := loadModuleList()
	if len(modules) == 0 {
		return nil
	}

	// Check for unknown modules not in safe list and not in baseline
	for _, mod := range modules {
		if safeModules[mod] {
			continue
		}

		key := "_kmod:" + mod
		_, known := store.GetRaw(key)
		if !known {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "kernel_module",
				Message:  fmt.Sprintf("Unknown kernel module loaded: %s", mod),
				Details:  "Not in safe list and not seen at baseline. Could indicate a rootkit.",
			})
		}
	}

	// Store current modules for future comparison
	for _, mod := range modules {
		store.SetRaw("_kmod:"+mod, "loaded")
	}

	return findings
}

func loadModuleList() []string {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var modules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 1 {
			modules = append(modules, fields[0])
		}
	}
	return modules
}

// CheckRPMIntegrity verifies critical system binaries haven't been modified.
// Only checks a small set of security-critical packages.
func CheckRPMIntegrity(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	criticalPackages := []string{
		"openssh-server",
		"shadow-utils",
		"sudo",
		"coreutils",
		"util-linux",
		"passwd",
	}

	for _, pkg := range criticalPackages {
		out, err := runCmd("rpm", "-V", pkg)
		if err != nil || out == nil {
			continue
		}

		output := strings.TrimSpace(string(out))
		if output == "" {
			continue
		}

		// Parse rpm -V output: each line starts with flags
		// S=size, 5=md5, T=mtime, etc. We care about S, 5, and M (mode)
		for _, line := range strings.Split(output, "\n") {
			if len(line) < 9 {
				continue
			}
			flags := line[:9]
			file := strings.TrimSpace(line[9:])

			// Skip config files (c) and documentation (d)
			if strings.Contains(line, " c ") || strings.Contains(line, " d ") {
				continue
			}

			// Check for size (S) or checksum (5) changes on binaries
			if strings.Contains(flags, "S") || strings.Contains(flags, "5") {
				// Only flag binary files, not configs
				if strings.HasPrefix(file, "/usr/bin/") || strings.HasPrefix(file, "/usr/sbin/") ||
					strings.HasPrefix(file, "/bin/") || strings.HasPrefix(file, "/sbin/") {
					findings = append(findings, alert.Finding{
						Severity: alert.Critical,
						Check:    "rpm_integrity",
						Message:  fmt.Sprintf("Modified system binary: %s (package: %s)", file, pkg),
						Details:  fmt.Sprintf("RPM verification flags: %s", flags),
					})
				}
			}
		}
	}

	return findings
}

// CheckMySQLUsers queries for MySQL users with elevated privileges
// that aren't standard cPanel-managed users.
func CheckMySQLUsers(_ *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	out, err := runCmd("mysql", "-N", "-B", "-e",
		"SELECT user, host FROM mysql.user WHERE Super_priv='Y' AND user NOT IN ('root','mysql.session','mysql.sys','mysql.infoschema','debian-sys-maint')")
	if err != nil || out == nil {
		return nil
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return nil
	}

	// Track known MySQL superusers
	hash := hashBytes(out)
	key := "_mysql_super_users"
	prev, exists := store.GetRaw(key)
	if exists && prev != hash {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "mysql_superuser",
			Message:  "MySQL superuser accounts changed",
			Details:  fmt.Sprintf("Current superusers:\n%s", output),
		})
	}
	store.SetRaw(key, hash)

	return findings
}

// CheckGroupWritablePHP scans for PHP files that are group-writable
// where the group is the web server (nobody/www-data). This allows
// webshells to persist by the web server modifying PHP files.
func CheckGroupWritablePHP(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Get web server group GIDs
	webGroupGIDs := getWebServerGIDs()
	if len(webGroupGIDs) == 0 {
		return nil
	}

	homeDirs, _ := os.ReadDir("/home")
	for _, homeEntry := range homeDirs {
		if !homeEntry.IsDir() {
			continue
		}
		docRoot := fmt.Sprintf("/home/%s/public_html", homeEntry.Name())
		scanGroupWritablePHP(docRoot, 4, webGroupGIDs, &findings)
	}

	return findings
}

func scanGroupWritablePHP(dir string, maxDepth int, webGIDs map[uint32]bool, findings *[]alert.Finding) {
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := dir + "/" + name

		if entry.IsDir() {
			// Skip known large/safe dirs
			if name == "cache" || name == "node_modules" || name == "vendor" {
				continue
			}
			scanGroupWritablePHP(fullPath, maxDepth-1, webGIDs, findings)
			continue
		}

		if !strings.HasSuffix(strings.ToLower(name), ".php") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check group-write bit
		if info.Mode()&0020 == 0 {
			continue
		}

		// Check if group is web server
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if webGIDs[stat.Gid] {
			*findings = append(*findings, alert.Finding{
				Severity: alert.High,
				Check:    "group_writable_php",
				Message:  fmt.Sprintf("Web-server group-writable PHP: %s", fullPath),
				Details:  fmt.Sprintf("Mode: %s, GID: %d", info.Mode(), stat.Gid),
			})
		}
	}
}

func getWebServerGIDs() map[uint32]bool {
	gids := make(map[uint32]bool)
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return gids
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		if name == "nobody" || name == "www-data" || name == "apache" || name == "www" {
			gid := uint32(0)
			fmt.Sscanf(fields[2], "%d", &gid)
			gids[gid] = true
		}
	}
	return gids
}

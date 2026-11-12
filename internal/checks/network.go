package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckOutboundConnections(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Parse /proc/net/tcp for established connections
	// Format: sl local_address rem_address st ...
	// local_address = IP:port we are listening/connecting from
	// rem_address = IP:port of the remote end
	data, err := osFS.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	listeners := collectListenSockets(lines, false)
	// Separate boots; sampled inode reuse keeps its earlier sighting.
	bootID, _ := osFS.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootID))
	stream := ""
	if boot != "" {
		stream = alert.SocketStream(boot)
	}
	now := time.Now()
	firstSeen := loadC2SocketsSeen(store, boot)
	seen := make(map[string]int64)
	sockets := make(map[string][]int)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		if fields[0] == "sl" {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		firstFinding := len(findings)
		// Ownership belongs to this kernel row, not to a later PID lookup.
		// Keep detections visible when an incomplete row has no usable UID.
		var uid uint64
		var uidKnown bool
		if len(fields) >= 8 {
			var err error
			uid, err = strconv.ParseUint(fields[7], 10, 32)
			uidKnown = err == nil
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		localIP, localPort := parseHexAddr(localAddr)
		remoteIP, remotePort := parseHexAddr(remoteAddr)

		if remoteIP == "" || remoteIP == "127.0.0.1" || remoteIP == "0.0.0.0" {
			continue
		}
		var inode string
		if len(fields) >= 10 {
			if n, err := strconv.ParseUint(fields[9], 10, 64); err == nil && n > 0 {
				inode = fields[9]
			}
		}

		// Check remote IP against C2 blocklist. A local socket with a
		// listener is the accept side: the listed address connected here.
		for _, blocked := range cfg.C2Blocklist {
			if remoteIP == blocked && !listeners.has(net.ParseIP(localIP), localPort) {
				details := fmt.Sprintf("Local socket: %s:%d", localIP, localPort)
				if inode != "" {
					details += ", socket inode " + inode
				}
				if uidKnown {
					details += fmt.Sprintf(", uid %d", uid)
				}
				f := alert.Finding{
					Severity: alert.Critical,
					Check:    "c2_connection",
					Message:  fmt.Sprintf("Connection to known C2 IP: %s:%d", remoteIP, remotePort),
					Details:  details,
					SourceIP: remoteIP,
				}
				if stream != "" && inode != "" {
					// A later scan of the same socket rereads the same
					// observation: it keeps the time first seen.
					at, known := firstSeen[inode]
					if !known {
						at = now.UnixNano()
					}
					seen[inode] = at
					f.Observation = alert.Observation{Producer: string(ProducerConnectionScan), Stream: stream, Cursor: inode, ObservedAt: time.Unix(0, at).UTC()}
					f.Attribution = admission.AttributionSocketDestination
				}
				if inode != "" {
					sockets[inode] = append(sockets[inode], len(findings))
				}
				findings = append(findings, f)
			}
		}

		// Check if OUR LOCAL port is a backdoor port (we're listening on it)
		// This catches backdoor listeners, not clients connecting from high ports
		for _, bp := range cfg.BackdoorPorts {
			if localPort == bp {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "backdoor_port",
					Message:  fmt.Sprintf("Listening on known backdoor port %d, connected from %s:%d", localPort, remoteIP, remotePort),
					SourceIP: remoteIP,
				})
			}
		}

		// Also check if we're connecting OUT to a backdoor port on a remote host
		// (e.g. reverse shell calling back to attacker's listener)
		// Skip if our local port is a known service (the remote port is just
		// the client's ephemeral port, not a backdoor listener)
		knownServicePorts := map[int]bool{
			21: true, 25: true, 26: true, 53: true, 80: true, 110: true,
			143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
			2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
			3306: true, 4190: true,
		}
		if !knownServicePorts[localPort] {
			for _, bp := range cfg.BackdoorPorts {
				if remotePort == bp {
					if isInfraIP(remoteIP, cfg.InfraIPs) {
						continue
					}
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "backdoor_port_outbound",
						Message:  fmt.Sprintf("Outbound connection to backdoor port: %s:%d", remoteIP, remotePort),
						Details:  fmt.Sprintf("Local port: %d", localPort),
						SourceIP: remoteIP,
					})
				}
			}
		}
		if uidKnown {
			for i := firstFinding; i < len(findings); i++ {
				AttributeSocketOwner(&findings[i], uint32(uid))
			}
		}
	}
	for inode, process := range socketProcesses(ctx, sockets) {
		for _, i := range sockets[inode] {
			findings[i].Details += ", " + process
		}
	}
	saveC2SocketsSeen(store, boot, seen)

	return findings
}

// c2SocketsSeenKey keeps when the C2 scan first saw each matched socket of
// the current boot, so a scan after a restart names the same observation.
const c2SocketsSeenKey = "_c2_sockets_seen"

type c2SocketsSeen struct {
	Boot string           `json:"boot"`
	Seen map[string]int64 `json:"seen"`
}

func loadC2SocketsSeen(store *state.Store, boot string) map[string]int64 {
	if store == nil || boot == "" {
		return nil
	}
	raw, ok := store.GetRaw(c2SocketsSeenKey)
	if !ok {
		return nil
	}
	var saved c2SocketsSeen
	if json.Unmarshal([]byte(raw), &saved) != nil || saved.Boot != boot {
		return nil
	}
	return saved.Seen
}

// saveC2SocketsSeen keeps only this scan's matched inodes. Reuse after an
// absent scan gets a new time, which cannot replace retained evidence.
func saveC2SocketsSeen(store *state.Store, boot string, seen map[string]int64) {
	if store == nil {
		return
	}
	if len(seen) == 0 {
		if _, ok := store.GetRaw(c2SocketsSeenKey); ok {
			store.DeleteRaw(c2SocketsSeenKey)
		}
		return
	}
	data, err := json.Marshal(c2SocketsSeen{Boot: boot, Seen: seen})
	if err != nil {
		return
	}
	store.SetRaw(c2SocketsSeenKey, string(data))
}

// socketProcesses names a process holding each socket inode in want, best
// effort: the first process found, with its executable when readable.
func socketProcesses(ctx context.Context, want map[string][]int) map[string]string {
	found := make(map[string]string)
	if len(want) == 0 {
		return found
	}
	fds, _ := osFS.Glob("/proc/*/fd/*")
	for _, fd := range fds {
		if ctx.Err() != nil || len(found) == len(want) {
			break
		}
		pid := strings.Split(strings.TrimPrefix(fd, "/proc/"), "/")[0]
		if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
			continue
		}
		target, err := osFS.Readlink(fd)
		if err != nil {
			continue
		}
		inode, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inode, ok = strings.CutSuffix(inode, "]")
		if _, wanted := want[inode]; !ok || !wanted || found[inode] != "" {
			continue
		}
		process := "process " + pid
		if exe, err := osFS.Readlink("/proc/" + pid + "/exe"); err == nil {
			process += " " + strconv.Quote(exe)
		}
		found[inode] = process
	}
	return found
}

// IsInfraIP reports whether ip is infrastructure the daemon must never act
// against: an operator infra entry (CIDR or address) or a Cloudflare edge.
// One implementation serves scans and the realtime path alike.
func IsInfraIP(ip string, infraNets []string) bool { return isInfraIP(ip, infraNets) }

// IsCloudflareIP reports whether ip is inside the published Cloudflare
// ranges the daemon last refreshed.
func IsCloudflareIP(ip net.IP) bool { return isCloudflareIP(ip) }

func isInfraIP(ip string, infraNets []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range infraNets {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Try CIDR first (e.g. "10.0.0.0/8")
		_, network, err := net.ParseCIDR(entry)
		if err == nil {
			if network.Contains(parsed) {
				return true
			}
			continue
		}
		// Fall back to plain IP match (e.g. "1.2.3.4")
		if entryIP := net.ParseIP(entry); entryIP != nil && entryIP.Equal(parsed) {
			return true
		}
	}
	// Also check Cloudflare IPs - these must never be blocked/challenged
	// because blocking a CF edge IP blocks thousands of legitimate users.
	// The detection/alert still fires; only the nftables action is skipped.
	if isCloudflareIP(parsed) {
		return true
	}
	return false
}

var (
	cfNets   []*net.IPNet
	cfNetsMu sync.RWMutex
)

// SetCloudflareNets updates the cached Cloudflare IP ranges.
// Called by the daemon after fetching CF IPs.
func SetCloudflareNets(cidrs []string) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, network)
		}
	}
	cfNetsMu.Lock()
	cfNets = nets
	cfNetsMu.Unlock()
}

func isCloudflareIP(ip net.IP) bool {
	cfNetsMu.RLock()
	defer cfNetsMu.RUnlock()
	for _, network := range cfNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	hexIP := parts[0]
	hexPort := parts[1]

	if len(hexIP) != 8 {
		return "", 0
	}

	// Parse little-endian hex IP
	var octets [4]byte
	for i := 0; i < 4; i++ {
		val := hexToByte(hexIP[6-2*i : 8-2*i])
		octets[i] = val
	}
	ip := net.IPv4(octets[0], octets[1], octets[2], octets[3]).String()

	port, ok := parseProcNetHexPort(hexPort)
	if !ok {
		return ip, 0
	}
	return ip, port
}

func parseProcNetHexPort(hexPort string) (int, bool) {
	if len(hexPort) != 4 {
		return 0, false
	}
	port := 0
	for i := 0; i < len(hexPort); i++ {
		c := hexPort[i]
		if !isHexDigit(c) {
			return 0, false
		}
		port = port*16 + hexVal(c)
	}
	return port, true
}

func hexToByte(s string) byte {
	if len(s) != 2 {
		return 0
	}
	// #nosec G115 -- hexVal returns 0..15; (h<<4)|h fits in a byte (0..255).
	return byte(hexVal(s[0])<<4 | hexVal(s[1]))
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}

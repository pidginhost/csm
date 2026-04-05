package firewall

// FirewallConfig defines the nftables firewall configuration.
type FirewallConfig struct {
	Enabled bool `yaml:"enabled"`

	// Open ports (IPv4)
	TCPIn  []int `yaml:"tcp_in"`
	TCPOut []int `yaml:"tcp_out"`
	UDPIn  []int `yaml:"udp_in"`
	UDPOut []int `yaml:"udp_out"`

	// IPv6 - enable dual-stack filtering
	IPv6    bool  `yaml:"ipv6"`
	TCP6In  []int `yaml:"tcp6_in"`  // if empty, uses tcp_in
	TCP6Out []int `yaml:"tcp6_out"` // if empty, uses tcp_out
	UDP6In  []int `yaml:"udp6_in"`  // if empty, uses udp_in
	UDP6Out []int `yaml:"udp6_out"` // if empty, uses udp_out

	// Ports restricted to infra IPs only
	RestrictedTCP []int `yaml:"restricted_tcp"`

	// Passive FTP range
	PassiveFTPStart int `yaml:"passive_ftp_start"`
	PassiveFTPEnd   int `yaml:"passive_ftp_end"`

	// Infra IPs (CIDR notation)
	InfraIPs []string `yaml:"infra_ips"`

	// Rate limiting (per-source-IP via nftables meters)
	ConnRateLimit      int  `yaml:"conn_rate_limit"` // new connections per minute per IP
	SYNFloodProtection bool `yaml:"syn_flood_protection"`
	ConnLimit          int  `yaml:"conn_limit"` // max concurrent connections per IP (0 = disabled)

	// Per-port flood protection - per-source rate limit per port
	PortFlood []PortFloodRule `yaml:"port_flood"`

	// UDP flood protection - per-source rate limit on UDP packets
	UDPFlood      bool `yaml:"udp_flood"`
	UDPFloodRate  int  `yaml:"udp_flood_rate"`  // packets per second
	UDPFloodBurst int  `yaml:"udp_flood_burst"` // burst allowance

	// Country blocking
	CountryBlock  []string `yaml:"country_block"` // ISO country codes
	CountryDBPath string   `yaml:"country_db_path"`

	// Ports to drop silently without logging (reduces log noise from scanners)
	DropNoLog []int `yaml:"drop_nolog"`

	// Max blocked IPs (prevents memory exhaustion, 0 = unlimited)
	DenyIPLimit     int `yaml:"deny_ip_limit"`
	DenyTempIPLimit int `yaml:"deny_temp_ip_limit"`

	// Outbound SMTP restriction - block outgoing mail except from allowed users
	SMTPBlock      bool     `yaml:"smtp_block"`
	SMTPAllowUsers []string `yaml:"smtp_allow_users"` // usernames allowed to send
	SMTPPorts      []int    `yaml:"smtp_ports"`

	// Dynamic DNS - resolve hostnames to IPs, update allowed set periodically
	DynDNSHosts []string `yaml:"dyndns_hosts"`

	// Logging
	LogDropped bool `yaml:"log_dropped"`
	LogRate    int  `yaml:"log_rate"` // log entries per minute
}

// PortFloodRule defines per-port connection rate limiting.
type PortFloodRule struct {
	Port    int    `yaml:"port"`
	Proto   string `yaml:"proto"`   // "tcp" or "udp"
	Hits    int    `yaml:"hits"`    // max new connections
	Seconds int    `yaml:"seconds"` // time window in seconds
}

// DefaultConfig returns a sensible default firewall configuration
// matching a typical cPanel server.
func DefaultConfig() *FirewallConfig {
	return &FirewallConfig{
		Enabled: false,
		TCPIn: []int{
			20, 21, 25, 26, 53, 80, 110, 143, 443, 465, 587,
			993, 995, 2077, 2078, 2079, 2080, 2082, 2083,
			2091, 2095, 2096,
		},
		TCPOut: []int{
			20, 21, 25, 26, 37, 43, 53, 80, 110, 113, 443,
			465, 587, 873, 993, 995, 2082, 2083, 2086, 2087,
			2089, 2195, 2325, 2703,
		},
		UDPIn:              []int{53, 443},
		UDPOut:             []int{53, 113, 123, 443, 873},
		RestrictedTCP:      []int{2086, 2087, 2325, 9443},
		PassiveFTPStart:    49152,
		PassiveFTPEnd:      65534,
		ConnRateLimit:      30,
		SYNFloodProtection: true,
		PortFlood: []PortFloodRule{
			{Port: 25, Proto: "tcp", Hits: 40, Seconds: 300},
			{Port: 465, Proto: "tcp", Hits: 40, Seconds: 300},
			{Port: 587, Proto: "tcp", Hits: 40, Seconds: 300},
		},
		UDPFlood:        true,
		UDPFloodRate:    100,
		UDPFloodBurst:   500,
		DropNoLog:       []int{23, 67, 68, 111, 113, 135, 136, 137, 138, 139, 445, 500, 513, 520},
		DenyIPLimit:     3000,
		DenyTempIPLimit: 500,
		SMTPBlock:       false,
		SMTPPorts:       []int{25, 465, 587},
		LogDropped:      true,
		LogRate:         5,
	}
}

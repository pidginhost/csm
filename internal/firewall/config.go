package firewall

// FirewallConfig defines the nftables firewall configuration.
type FirewallConfig struct {
	Enabled bool `yaml:"enabled"`

	// Open ports
	TCPIn  []int `yaml:"tcp_in"`
	TCPOut []int `yaml:"tcp_out"`
	UDPIn  []int `yaml:"udp_in"`
	UDPOut []int `yaml:"udp_out"`

	// Ports restricted to infra IPs only
	RestrictedTCP []int `yaml:"restricted_tcp"`

	// Passive FTP range
	PassiveFTPStart int `yaml:"passive_ftp_start"`
	PassiveFTPEnd   int `yaml:"passive_ftp_end"`

	// Infra IPs (CIDR notation)
	InfraIPs []string `yaml:"infra_ips"`

	// Rate limiting
	ConnRateLimit      int  `yaml:"conn_rate_limit"` // per-IP new connections per minute
	SYNFloodProtection bool `yaml:"syn_flood_protection"`

	// Country blocking
	CountryBlock  []string `yaml:"country_block"` // ISO country codes
	CountryDBPath string   `yaml:"country_db_path"`

	// Logging
	LogDropped bool `yaml:"log_dropped"`
	LogRate    int  `yaml:"log_rate"` // log entries per minute
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
		RestrictedTCP:      []int{2086, 2087, 2325},
		PassiveFTPStart:    49152,
		PassiveFTPEnd:      65534,
		ConnRateLimit:      30,
		SYNFloodProtection: true,
		LogDropped:         true,
		LogRate:            5,
	}
}

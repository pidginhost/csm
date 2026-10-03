package alert

// SubnetSprayCIDR returns the subnet a mail or SMTP password spray names in
// its structured CIDRs. Other findings, and a spray without exactly one
// subnet, return "": a crawl's subnets are block targets, not an attacker
// identity.
func SubnetSprayCIDR(f Finding) string {
	switch f.Check {
	case "mail_subnet_spray", "smtp_subnet_spray":
	default:
		return ""
	}
	if len(f.CIDRs) != 1 {
		return ""
	}
	return f.CIDRs[0]
}

// AttackerAddress returns what a finding names as the attack source:
// SourceIP, or the subnet of a password spray. SourceIP comes first so a
// spray parked by an older daemon, with its subnet in SourceIP, reads the
// same as a new one.
func AttackerAddress(f Finding) string {
	if f.SourceIP != "" {
		return f.SourceIP
	}
	return SubnetSprayCIDR(f)
}

package daemon

// Reasons recorded for automatic blocks that do not spend the scan budget.
// The offline replay tool recognises these paths by them, so they are
// spelled here once; block_reasons_test.go holds them to the replay's
// prefixes and refuses a copy typed at a call site.
const (
	challengeTimeoutReasonPrefix = "challenge timeout: "
	centralIntelBlockReason      = "central-intel (locally corroborated)"
	credentialSprayReasonPrefix  = "CSM credential_spray: "
	incidentReasonPrefix         = "CSM incident: "
)

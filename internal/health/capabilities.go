package health

// Capabilities is the static list of features this build supports. Phpanel
// reads it via /api/v1/capabilities to feature-detect without version
// sniffing. Add a string here when shipping a feature; remove when ripping
// one out. The set is sorted for stable JSON output.
func Capabilities() []string {
	return []string{
		"confd.dropins.v1",         // P1
		"profile.phpanel-agent.v1", // P1
		"status.json.v1",           // P2
		"capabilities.v1",          // P2
		"doctor.v1",                // P2
		"config.schema.v1",         // P2
		"sd_notify.ready",          // P2
		"audit.fields.tenant.v1",   // P3
		"webhook.phpanel.v1",       // P3
		"events.sse.v1",            // P3
		"token.scope.readonly.v1",  // P3
	}
}

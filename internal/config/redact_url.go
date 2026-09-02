package config

import "net/url"

const redactedURLTail = "[REDACTED]"

// RedactURL keeps only the scheme and host of a URL for display. Webhook,
// heartbeat and callback URLs carry their credential in the path, query or
// userinfo (Slack and Discord webhooks, healthcheck pings, token query
// parameters), so everything past the host is replaced. A bare
// scheme://host[:port][/] is returned unchanged; an unparseable value is
// hidden entirely.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return redactedURLTail
	}
	bare := u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && u.RawPath == ""
	if bare {
		return raw
	}
	return u.Scheme + "://" + u.Host + "/" + redactedURLTail
}

// urlScalarPaths are config keys whose value is a credential-bearing URL;
// hot-reload diff logging shows them through RedactURL.
var urlScalarPaths = map[string]struct{}{
	"alerts.webhook.url":                 {},
	"alerts.heartbeat.url":               {},
	"auto_response.verdict_callback.url": {},
	"reputation.rspamd.url":              {},
	"reputation.upstream.url":            {},
}

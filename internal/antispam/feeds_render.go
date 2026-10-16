package antispam

// Map redirect names, for Settings.SkipMaps (feeds spec section 5.4).
const (
	RedirectForgedRecipients = "forged_recipients"
	RedirectMID              = "mid"
	RedirectMimeTypes        = "mime_types"
	RedirectWhitelist        = "whitelist"
	RedirectMultimap         = "multimap"
)

// MapRedirectNames lists the map redirects in write order.
func MapRedirectNames() []string {
	return []string{RedirectForgedRecipients, RedirectMID, RedirectMimeTypes, RedirectWhitelist, RedirectMultimap}
}

package geoip

// KnownEditions returns the MaxMind database editions CSM supports in the
// settings UI. The first slice is the free GeoLite2 family; the second is
// the paid GeoIP2 family. The lists are curated to what MaxMind actually
// publishes via the geoipupdate protocol; adding an edition here makes it
// selectable in the Settings → GeoIP → Database editions dropdown.
func KnownEditions() (free, commercial []string) {
	free = []string{
		"GeoLite2-City",
		"GeoLite2-Country",
		"GeoLite2-ASN",
	}
	commercial = []string{
		"GeoIP2-City",
		"GeoIP2-Country",
		"GeoIP2-ISP",
		"GeoIP2-Domain",
		"GeoIP2-Connection-Type",
		"GeoIP2-Anonymous-IP",
		"GeoIP2-Enterprise",
	}
	return free, commercial
}

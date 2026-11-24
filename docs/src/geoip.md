# GeoIP

CSM uses the MaxMind GeoLite2 databases to show where an IP address is located and which network it belongs to. You supply a free MaxMind account, and CSM downloads and updates the databases itself.

## Configuration

Create a free account at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup), then set the account ID and license key:

```yaml
geoip:
  account_id: "YOUR_MAXMIND_ACCOUNT_ID"
  license_key: "YOUR_MAXMIND_LICENSE_KEY"
  editions:
    - GeoLite2-City
    - GeoLite2-ASN
  auto_update: true
  update_interval: 24h
```

## Features

- CSM reads the country and city from the City database.
- The ASN database gives ISP, organization and autonomous system number.
- CSM downloads the databases on first use.
- CSM updates them every 24 hours. The interval is configurable.
- For detailed ISP and organization information, CSM queries RDAP. It caches successful lookups for 24 hours and failures for 10 minutes.

## Where it's used

- The threat intel page uses it for top attackers and IP lookup.
- The firewall audit log shows country flags.
- Login alerts carry geographic context.
- Country-based login suppression (`trusted_countries`) uses the country.
- Country blocking uses separate firewall CIDR lists. Update them with `csm firewall update-geoip`.

## CLI

```bash
csm update-geoip                    # Manual database update
csm firewall update-geoip           # Download country CIDR blocks
csm firewall lookup <ip>            # GeoIP + block status lookup
```

An address lookup reports country, city, ASN, organization and network when the local databases supply them. It leaves out fields that are missing.

When an address matches country blocks, the lookup keeps every matching country. A country-block match does not prevent ASN or city enrichment.

## API

```
GET  /api/v1/geoip              IP geolocation (?ip=&detail=1)
POST /api/v1/geoip/batch        Batch lookup (array of IPs)
```

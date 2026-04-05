# GeoIP

MaxMind GeoLite2 integration for IP geolocation and ASN enrichment.

## Features

- **City database** - country, city, latitude/longitude
- **ASN database** - ISP, organization, autonomous system number
- **Auto-download** on first use
- **Auto-update** every 24 hours (configurable)
- **RDAP fallback** for detailed ISP/org info (cached 24h)

## Where It's Used

- Threat intel page (top attackers, IP lookup)
- Firewall audit log (country flags)
- Login alerts (geographic context)
- Country-based login suppression (`trusted_countries`)
- Country blocking (firewall CIDR ranges)

## Configuration

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

Free account: [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)

## CLI

```bash
csm update-geoip                    # Manual database update
csm firewall update-geoip           # Download country CIDR blocks
csm firewall lookup <ip>            # GeoIP + block status lookup
```

## API

```
GET  /api/v1/geoip              IP geolocation (?ip=&detail=1)
POST /api/v1/geoip/batch        Batch lookup (array of IPs)
```

# CSF to CSM Firewall Migration

Step-by-step guide to replace CSF (ConfigServer Firewall) with CSM's native nftables engine.

## Prerequisites

- CSM daemon running and stable (`systemctl status csm`)
- SSH access from an infra IP (verify: `csm firewall lookup <your-IP>`)
- Current CSF running (`csf -v`)
- Two SSH sessions open (one for work, one as safety net)
- Firewall config already tuned in csm.yaml (ports, IPv6, rate limits, etc.)

## Pre-flight

```bash
# 1. Verify your IP is in infra range — CRITICAL
csm firewall lookup <your-current-IP>
# Must show INFRA — if not, add your IP to infra_ips in csm.yaml first

# 2. Verify firewall config looks correct
csm firewall status
csm firewall ports

# 3. Dry-run migration to see what CSF has
csm firewall migrate-from-csf
# Review the report — note allowed/blocked counts
```

## Migration

### Step 1: Enable firewall with safety timer

```bash
# Enable in config
sed -i 's/enabled: false/enabled: true/' /opt/csm/csm.yaml

# Apply with commit-confirmed (auto-rollback in 3 minutes if not confirmed)
csm firewall apply-confirmed 3
```

### Step 2: Test connectivity

**In your SECOND SSH session** (do NOT close the first):
```bash
# Can you SSH in?
ssh -p 2325 root@host.internal.example

# Can you reach WHM?
curl -sk https://localhost:2087 | head -1

# Can you reach cPanel?
curl -sk https://localhost:2083 | head -1

# Can you reach websites?
curl -sk https://localhost:443 | head -1
```

### Step 3: Confirm or wait for rollback

```bash
# If everything works:
csm firewall confirm

# If something is broken: DO NOTHING — wait 3 minutes for auto-rollback
```

### Step 4: Import CSF blocked IPs

**Do NOT use `migrate-from-csf --apply`** — it overwrites your entire firewall
config (ports, rate limits, IPv6, etc.) with CSF-derived defaults.

Instead, import only the blocked/allowed IPs:

```bash
# Import CSF denied IPs (one-liner reads csf.deny, blocks each IP)
grep -v '^#' /etc/csf/csf.deny | grep -v '^\$' | grep -v '^$' | while read line; do
  ip=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
  reason=$(echo "$line" | sed 's/.*#//' | xargs)
  [ -n "$ip" ] && csm firewall deny "$ip" "$reason" 2>/dev/null
done

# Import CSF allowed IPs (plain IPs only — port-specific handled separately)
grep -v '^#' /etc/csf/csf.allow | grep -v '^\$' | grep -v '^$' | grep -v '|' | grep -v 'Include' | while read line; do
  ip=$(echo "$line" | awk '{print $1}')
  reason=$(echo "$line" | sed 's/.*#//' | xargs)
  [ -n "$ip" ] && csm firewall allow "$ip" "$reason" 2>/dev/null
done

# Import port-specific allows (e.g. MySQL access)
grep '|' /etc/csf/csf.allow | grep -v '^#' | while read line; do
  ip=$(echo "$line" | grep -oP 's=\K[0-9./]+')
  port=$(echo "$line" | grep -oP 'd=\K[0-9]+')
  reason=$(echo "$line" | sed 's/.*#//' | xargs)
  [ -n "$ip" ] && [ -n "$port" ] && csm firewall allow-port "$ip" "$port" "$reason" 2>/dev/null
done

# Apply port-specific allows (they need a restart to take effect)
csm firewall restart
```

### Step 5: Disable CSF

```bash
csf -x
systemctl stop csf lfd
systemctl disable csf lfd
```

### Step 6: Re-baseline CSM

```bash
systemctl stop csm
rm -f /opt/csm/state/csm.lock
csm baseline
csm baseline    # double baseline normalizes YAML ordering
systemctl start csm
```

### Step 7: Disable cpanel-service (replaced by CSM API)

```bash
systemctl stop cpanel-service
systemctl disable cpanel-service
```

## Post-migration verification

```bash
# Firewall active
csm firewall status

# Services accessible
curl -sk https://localhost:2087 | head -1
curl -sk https://localhost:2083 | head -1
curl -sk https://localhost:443  | head -1

# Blocked IPs imported
csm firewall grep brute | head -5

# Audit log shows activity
csm firewall audit 20

# Check dmesg for CSM-DROP entries (replaces CSF's "Firewall:" entries)
dmesg | grep CSM-DROP | tail -5

# Test apiuser unban API (from pidginhost.com server)
curl -sk -H "Authorization: Bearer $CSM_AUTH_TOKEN" \
  "https://host.internal.example:9443/api/v1/firewall/check?ip=8.8.8.8"
```

## Rollback

If something goes wrong after confirmation:

```bash
# Re-enable CSF immediately
csf -e
systemctl start csf lfd

# Disable CSM firewall
sed -i 's/enabled: true/enabled: false/' /opt/csm/csm.yaml
systemctl restart csm
```

## Safety guarantees

1. **Infra IPs are immune** — infra ACCEPT rules come BEFORE blocked DROP rules in the nftables chain; BlockIP() refuses to block any IP in the infra set
2. **Commit-confirmed** — `apply-confirmed N` auto-rollbacks if `confirm` is not run within N minutes
3. **Atomic apply** — all rules applied in a single netlink transaction; kernel keeps old rules on failure
4. **cphulk integration** — unblock operations also flush cPanel brute force detector
5. **CSF fallback** — during transition, unblock also calls `csf -dr` for belt-and-suspenders

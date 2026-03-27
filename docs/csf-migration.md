# CSF to CSM Firewall Migration

Step-by-step guide to replace CSF (ConfigServer Firewall) with CSM's native nftables engine.

## Prerequisites

- CSM daemon running and stable (`systemctl status csm`)
- SSH access from an infra IP (verify: `csm firewall lookup <your-IP>`)
- Current CSF running (`csf -v`)
- Two SSH sessions open (one for work, one as safety net)

## Pre-flight

```bash
# 1. Dry-run migration — review what will be migrated
csm firewall migrate-from-csf

# 2. Verify your IP is in infra range
csm firewall lookup <your-current-IP>
# Must show INFRA — if not, add your IP to infra_ips in csm.yaml first

# 3. Verify firewall config matches CSF
csm firewall ports
csm firewall status
```

## Migration (with safety timer)

```bash
# 4. Enable firewall in config
sed -i 's/enabled: false/enabled: true/' /opt/csm/csm.yaml

# 5. Apply with commit-confirmed (auto-rollback in 3 minutes if not confirmed)
csm firewall apply-confirmed 3

# 6. TEST IMMEDIATELY in your second SSH session:
#    - Can you SSH in?
#    - Can you reach WHM (https://server:2087)?
#    - Can you reach cPanel (https://server:2083)?

# 7. If everything works, CONFIRM:
csm firewall confirm

# 8. If something is broken, WAIT 3 minutes — rules auto-rollback
```

## Migrate CSF state

```bash
# 9. Import CSF blocked/allowed IPs
csm firewall migrate-from-csf --apply

# 10. Restart to load port-specific allows into rules
csm firewall restart
```

## Disable CSF

```bash
# 11. Stop CSF (firewall already handled by CSM)
csf -x
systemctl stop csf lfd
systemctl disable csf lfd

# 12. Re-baseline CSM (config changed)
systemctl stop csm
rm -f /opt/csm/state/csm.lock
csm baseline
csm baseline   # double baseline normalizes YAML
systemctl start csm
```

## Post-migration verification

```bash
# Check firewall is active
csm firewall status

# Check services accessible
curl -sk https://localhost:2087 | head -1    # WHM
curl -sk https://localhost:2083 | head -1    # cPanel
curl -sk https://localhost:443  | head -1    # Web

# Check recent audit log
csm firewall audit 20

# Monitor dmesg for new CSM-DROP entries
dmesg | grep CSM-DROP | tail -5
```

## Rollback (if needed after confirmation)

```bash
# Re-enable CSF immediately
csf -e
systemctl start csf lfd

# Disable CSM firewall
sed -i 's/enabled: true/enabled: false/' /opt/csm/csm.yaml
systemctl restart csm
```

## Safety guarantees

1. **Infra IPs are never blocked** — the engine refuses to block any IP in the infra set, and infra ACCEPT rules come before block rules in the chain
2. **Commit-confirmed** — `apply-confirmed N` auto-rollbacks to the previous nftables ruleset if `confirm` is not run within N minutes
3. **Atomic apply** — all rules are applied in a single netlink transaction; if anything fails, the kernel keeps the old ruleset
4. **State persistence** — blocked/allowed IPs survive daemon restart

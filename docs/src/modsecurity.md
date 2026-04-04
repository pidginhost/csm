# ModSecurity Integration

CSM manages ModSecurity (WAF) configuration, deploys custom rules, and provides a web UI for rule overrides and escalation.

## Features

- **Custom CSM rules** — IDs 900000-900999 in `configs/csm_modsec_custom.conf`
- **Rule override management** — `SecRuleRemoveById` directives for false positive suppression
- **Escalation control** — change rule severity or action per-rule
- **WAF event log parsing** — correlates events by IP, URI, and rule ID
- **Hot-reload** — apply changes without Apache restart

## Web UI Pages

**ModSecurity** (`/modsec`) — WAF status overview, event log, active block list

**ModSec Rules** (`/modsec/rules`) — per-rule management:
- View loaded rules with descriptions
- Enable/disable individual rules
- Override rule severity or action
- Deploy custom rules

## API Endpoints

```
GET  /api/v1/modsec/stats            WAF statistics
GET  /api/v1/modsec/blocks           Blocked request log
GET  /api/v1/modsec/events           WAF event details
GET  /api/v1/modsec/rules            Loaded rules list
POST /api/v1/modsec/rules/apply      Apply custom rules
POST /api/v1/modsec/rules/escalation Change rule severity/action
```

#!/bin/bash
# rpm posttrans fires after the whole transaction, including any
# preremove/postremove the old package may have run. Re-arm the binary
# hardening and install marker so upgrades from versions that tore both
# down unconditionally still end with the configured binary protection.
/opt/csm/csm config apply-immutability 2>/dev/null || true
mkdir -p /var/lib/csm 2>/dev/null || true
touch /var/lib/csm/.pkg-installed 2>/dev/null || true

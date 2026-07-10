#!/bin/bash
# Pre-removal hook.
#
# rpm passes $1=0 on full uninstall and $1=1 on upgrade-leftover. deb passes
# "remove" or "upgrade". On upgrade the new package's postinstall has already
# unpacked, restarted, and restored the configured binary protection. Running
# the uninstall body here would alter that protection and disable the unit.
if [ "${1:-}" = "1" ] || [ "${1:-}" = "upgrade" ]; then
    exit 0
fi

chattr -i /opt/csm/csm 2>/dev/null || true
systemctl stop csm.service 2>/dev/null || true
systemctl disable csm.service 2>/dev/null || true

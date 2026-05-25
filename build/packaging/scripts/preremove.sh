#!/bin/bash
# Pre-removal hook.
#
# rpm passes $1=0 on full uninstall and $1=1 on upgrade-leftover. deb passes
# "remove" or "upgrade". On upgrade the new package's postinstall has already
# unpacked, restarted, and re-applied chattr +i to the binary; running the
# uninstall body here would strip that immutable flag and disable the unit,
# leaving the host worse off than before.
if [ "${1:-}" = "1" ] || [ "${1:-}" = "upgrade" ]; then
    exit 0
fi

chattr -i /opt/csm/csm 2>/dev/null || true
systemctl stop csm.service 2>/dev/null || true
systemctl disable csm.service 2>/dev/null || true

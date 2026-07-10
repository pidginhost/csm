#!/bin/bash
# Clear immutable / append-only on the CSM binary before the package
# manager unpacks the new one. Postinstall restores the protection selected
# by integrity.immutable. Without this step rpm/deb upgrade fails on hosts
# where the previous version hardened /opt/csm/csm, because rpm cannot
# overwrite an immutable file.
set -e

CHATTR="$(command -v chattr || true)"
if [ -n "$CHATTR" ]; then
    [ -e /opt/csm/csm ] && "$CHATTR" -i -a /opt/csm/csm 2>/dev/null || :
    [ -d /opt/csm ]     && "$CHATTR" -i -a /opt/csm     2>/dev/null || :
fi

exit 0

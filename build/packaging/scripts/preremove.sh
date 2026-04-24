#!/bin/bash
# Stop all CSM services before removal
chattr -i /opt/csm/csm 2>/dev/null || true
systemctl stop csm.service 2>/dev/null || true
systemctl disable csm.service 2>/dev/null || true

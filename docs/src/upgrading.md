# Upgrading

## deploy.sh (recommended)

```bash
/opt/csm/deploy.sh upgrade
```

This will:
1. Stop the daemon
2. Back up the current binary
3. Download the new version
4. Verify SHA256 checksum
5. Extract UI assets and rules
6. Rehash config
7. Restart the daemon

Rolls back automatically on failure.

## RPM/DEB

```bash
yum update csm              # RPM
dpkg -i csm_NEW.deb         # DEB
```

Package managers handle stop/start automatically.

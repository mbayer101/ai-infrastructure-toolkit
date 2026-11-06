#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root." >&2
  exit 1
fi

BACKUP_DIR="/var/backups/pve-configs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
STAGING_DIR="$BACKUP_DIR/staging_$TIMESTAMP"
ARCHIVE_NAME="pve-config-backup-$TIMESTAMP.tar.gz"
RETENTION_DAYS=7

mkdir -p "$BACKUP_DIR" "$STAGING_DIR"

if [ -f /var/lib/pve-cluster/config.db ]; then
    mkdir -p "$STAGING_DIR/var/lib/pve-cluster"
    sqlite3 /var/lib/pve-cluster/config.db ".backup '$STAGING_DIR/var/lib/pve-cluster/config.db'"
fi

[ -d /etc/corosync ] && cp -r /etc/corosync "$STAGING_DIR/etc/"
mkdir -p "$STAGING_DIR/etc/network"
[ -f /etc/network/interfaces ] && cp /etc/network/interfaces "$STAGING_DIR/etc/network/"
[ -f /etc/hostname ] && cp /etc/hostname "$STAGING_DIR/etc/"
[ -f /etc/hosts ] && cp /etc/hosts "$STAGING_DIR/etc/"

tar -czf "$BACKUP_DIR/$ARCHIVE_NAME" -C "$BACKUP_DIR" "staging_$TIMESTAMP"
rm -rf "$STAGING_DIR"
find "$BACKUP_DIR" -name "pve-config-backup-*.tar.gz" -mtime +$RETENTION_DAYS -delete
echo "[+] Backup successfully created: $BACKUP_DIR/$ARCHIVE_NAME"


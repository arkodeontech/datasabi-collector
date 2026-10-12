#!/bin/sh
# Debian only: "apt purge" removes usage history. The system user is kept,
# as Debian policy recommends.
set -e

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/datasabi
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0

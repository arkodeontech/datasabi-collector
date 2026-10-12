#!/bin/sh
# Runs before the collector package is removed. Upgrades keep the service running;
# postinst restarts it with the new binary.
set -e

case "$1" in
    upgrade|1|failed-upgrade) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl stop datasabi-collector.service >/dev/null 2>&1 || true
    systemctl disable datasabi-collector.service >/dev/null 2>&1 || true
fi
exit 0

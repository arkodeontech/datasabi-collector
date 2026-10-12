#!/bin/sh
# Runs after the collector package is installed or upgraded (deb and rpm).
set -e

case "$1" in
    abort-*) exit 0 ;;
esac

if ! getent group datasabi >/dev/null; then
    groupadd --system datasabi
fi
if ! getent passwd datasabi >/dev/null; then
    useradd --system --gid datasabi --no-create-home --home-dir /var/lib/datasabi \
        --shell /usr/sbin/nologin --comment "DataSabi collector" datasabi
fi

# Let the person who installed DataSabi use it without sudo.
INSTALLER="${SUDO_USER:-}"
if [ -z "$INSTALLER" ] && [ -n "${PKEXEC_UID:-}" ]; then
    INSTALLER="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
fi
if [ -n "$INSTALLER" ] && [ "$INSTALLER" != "root" ]; then
    if ! id -nG "$INSTALLER" | tr ' ' '\n' | grep -qx datasabi; then
        usermod -aG datasabi "$INSTALLER"
        echo "DataSabi: added $INSTALLER to the 'datasabi' group. Log out and back in to start using the app."
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable datasabi-collector.service >/dev/null 2>&1 || true
    systemctl restart datasabi-collector.service || true
fi
exit 0

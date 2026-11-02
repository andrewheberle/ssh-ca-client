#!/bin/sh
# Stop the system timers when the package is removed, but not on upgrade.
# Whether they are enabled is kept until the package is purged.
set -e

if [ -d /run/systemd/system ] && [ "$1" = "remove" ]; then
	systemctl stop host-ssh-certificate-renewal.timer user-ssh-krl-refresh.timer || true
fi

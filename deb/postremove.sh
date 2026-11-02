#!/bin/sh
# On purge the links left by enabling the system timers are removed, as the
# unit files are already gone so systemctl disable can't be used.
set -e

if [ "$1" = "purge" ]; then
	rm -f /etc/systemd/system/timers.target.wants/host-ssh-certificate-renewal.timer \
		/etc/systemd/system/timers.target.wants/user-ssh-krl-refresh.timer
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi

#!/bin/sh
# nfpm does not handle systemd units like debhelper does, so it is done here.
# A reload picks up new or changed units, which also applies a changed
# schedule. The timers are enabled by the admin, not here, but each system
# timer that is enabled is started: removing the package stops the timers but
# keeps them enabled until purge, so a reinstall would otherwise leave them
# inactive until the next boot. On an upgrade they are already running.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true

	if [ "$1" = "configure" ]; then
		for timer in host-ssh-certificate-renewal.timer user-ssh-krl-refresh.timer; do
			if systemctl is-enabled --quiet "$timer"; then
				systemctl start "$timer" || true
			fi
		done
	fi
fi

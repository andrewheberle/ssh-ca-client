#!/bin/sh
# nfpm does not reload systemd like debhelper does, so new or changed units
# are picked up here. The timers are not enabled or restarted: they are
# enabled by the admin, and a reload applies a changed schedule.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi

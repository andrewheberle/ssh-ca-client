# Host commands run a reload command only when certificates change

From OpenSSH 9.8 the `sshd` listener reads host certificates once, when it starts or is reloaded, and hands that copy to every connection; 9.7 and earlier re-read the files for each connection. A renewal revokes the certificate it replaces, so on 9.8+ a host that renews without reloading `sshd` presents a revoked certificate, and then an expired one. So `host`, `host --renew` and `revoke --host` take `--reload-command`, run with `/bin/sh -c` once at the end of the command if any host certificate file was written or deleted, compared with what the stores held when the command started. A change counts whatever the exit status, so a run where one key renewed and another failed still reloads, as does a run interrupted after a certificate was written. A failing reload command fails the command but keeps the certificates. The command runs regardless of the OpenSSH version, as a reload is harmless on older versions and version strings are unreliable to parse. The packaged renewal unit passes `systemctl try-reload-or-restart ssh.service`.

## Considered Options

- **`ExecStartPost=` in the renewal unit**: no code, but systemd skips it when `ExecStart` fails, which misses the partial-failure case, and it reloads `sshd` every day even when nothing was renewed, re-reading `sshd_config` along the way.
- **A systemd `.path` unit watching the certificate files**: independent of the CLI, but it hard-codes the default key paths, needs two more units, and relies on inotify semantics for atomic renames and deletions.
- **A built-in `--reload-sshd`**: tidier to use, but the CLI would have to know each init system and unit name (`ssh` on Debian and Ubuntu, `sshd` on RHEL, `service sshd reload` on BSD).

## Consequences

The packaged unit names `ssh.service`, which is right for the Debian/Ubuntu package it ships in. Hosts that copy the unit to RHEL and derivatives must change it to `sshd.service`. Without `--reload-command`, a changed certificate logs a reminder to reload `sshd` instead.

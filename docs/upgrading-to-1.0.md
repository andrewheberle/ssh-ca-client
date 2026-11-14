# Upgrading to 1.0

ssh-ca-client 1.0.0 is the first release covered by semantic versioning. It
tightens what the client accepts on its command line and in its
configuration, and sandboxes the packaged systemd units, so a script, drop-in
or configuration that 0.x accepted can be refused. This page covers what to
check before you upgrade from any 0.x release. The changelog lists every
change.

## What 1.0.0 promises

From 1.0.0, a breaking change to any of the following needs a new major
version:

- The CLI commands and flags, and the GUI.
- The configuration file format, and the matching registry values on Windows.
- The Windows Group Policy settings (`policy/`): the Policy registry key and
  value names.
- The Windows Event Log source name, `Serverless SSH CA Client`.
- The packaged systemd units: an enabled unit keeps doing the same job across
  upgrades. It writes the same files, renews the same host certificates, and
  your drop-ins still apply. Unit names, contents and schedules are not
  covered.
- Paths that admins or other programs point at:
  - **deb**: `/usr/bin/ssh-ca-client-cli`, `/usr/bin/ssh-ca-client`,
    `/etc/serverless-ssh-ca/config.yml`, the KRL files
    `/etc/ssh/revocation_list` and `~/.ssh/revocation_list` written by the
    units, and host certificates written as `<key>-cert.pub` next to the
    host keys.
  - **snap**: `/snap/bin/ssh-ca-client.ssh-ca-client-cli`,
    `/snap/bin/ssh-ca-client`, and the `snap set ssh-ca-client` keys for the
    configuration.
  - **MSI**: `ssh-ca-client-cli.exe` and `ssh-ca-client.exe` in the install
    directory, the configuration key
    `HKLM\SOFTWARE\Andrew Heberle\Serverless SSH CA Client` (or the same key
    under HKCU with `--config HKCU`), the Policy key
    `HKLM\SOFTWARE\Policies\Serverless SSH CA Client`, and the Run value
    `Serverless SSH CA Client`.
- Upgrades. A 1.x release keeps working with whatever 0.27.x or an earlier 1.x
  release stored, migrating it if needed, so no one has to log in again or
  re-issue certificates.

These are not covered and can change in any release:

- Stored state: keyring entries, the token store, and state and cache files.
  Running an older release after a newer one has migrated its state is not
  supported.
- Help text and its layout.
- Field names in `--json` logs.
- Specific non-zero exit codes. Only zero for success and non-zero for failure
  is covered.
- Windows Event Log event IDs.
- The ADMX namespace, which changes whenever the templates change (see
  [Windows Group Policy](#windows-group-policy)).
- Paths nothing outside the package points at, such as icons, the `.desktop`
  file, where unit files are installed, and the snap's generated
  `config.yml`.

There is no Go API. Every package is under `internal/`, so the module has no
importable packages.

## Before you upgrade

1. **Check the CA.** The client needs a CA that serves `/api/v4`:
   serverless-ssh-ca 1.0.0 or later is recommended. ssh-ca-client has used
   only `/api/v4` since 0.24.0.
2. **Check the configuration** against
   [Configuration](#configuration). After upgrading, run
   `ssh-ca-client-cli krl`: it loads the configuration and fetches the user
   KRL, but writes nothing.
3. **Check scripts, cron jobs and systemd drop-ins** that run
   `ssh-ca-client-cli`, against [Command line](#command-line).
4. **Check systemd drop-ins** that renew keys, write a KRL, or run a reload
   command that writes, outside `/etc/ssh` (see [systemd units](#systemd-units)).
5. **On Windows, import the new Group Policy templates** in Intune or your
   Central Store (see [Windows Group Policy](#windows-group-policy)).
6. **If you install the MSI with custom properties**, give them again when
   upgrading (see [MSI](#msi)).

Keys, certificates and refresh tokens are stored exactly as in 0.27.x, so
nobody needs to log in again or re-issue certificates after upgrading.

## Command line

Commands now refuse input that 0.x silently ignored:

- **Positional arguments are an error** for every command. Before, a value
  given without its flag was dropped, and the command did its default action
  instead: `revoke --yes 999` revoked the current certificate rather than
  serial 999, and `krl /etc/ssh/revocation_list` wrote nothing.
- **Flags that only apply with another flag** are an error without it:
  - `revoke --key` needs `--host`. Before, it revoked the user certificate
    instead of the host certificates. `revoke --serial` on its own still
    revokes user certificate serials.
  - `host --force` and `--renew-at` need `--renew`.
  - `login --add` can't be combined with `--force`, `--life` or
    `--skip-agent`.
- **`krl --force` is removed.** It has done nothing since 0.23.0.

Some flags were renamed so that every flag uses the same, hyphenated, style.
The old names still work in every 1.x release, but print a deprecation
warning, and are left out of the help and docs:

| Command | Old name | New name |
|---|---|---|
| `generate` | `--dryrun` | `--dry-run` |
| `host` | `--renewat` | `--renew-at` |
| `krl` | `-f` | `-o` (short for `--out`) |
| GUI | `--renew` | `--refresh-before` |
| GUI | `--log.file` | `--log-file` |

The GUI's `--renew` was renamed because getting a new user certificate with a
refresh token is a refresh, and renewal is the host certificate exchange (see
[GLOSSARY.md](../GLOSSARY.md)).

## Configuration

The configuration is now checked strictly, so a mistake is reported instead
of being silently ignored:

- **Unknown keys are an error**, as are YAML keys in another case, such as
  `CA_URL`, and nested keys. Before, a misspelt optional key left its setting
  at the default: `scope:` dropped `offline_access`, and `redirect-url:`
  kept the default port. Registry value names on Windows can be in any case.
- **Values must have the right type.** `scopes` must be a list (a
  REG_MULTI_SZ on Windows), and a `client_id` that YAML would read as a
  number must be quoted.
- **`trusted_ca` holds exactly one key.** Before, any keys after the first
  were dropped.
- **`ca_url` and `issuer` must use `https`**, unless the host is `localhost`
  or a loopback address. Over plain `http`, the tokens sent to the CA and the
  identity provider's signing keys can be read or replaced on the network.
- **On Windows, an empty registry value is treated as not set**, in both the
  configuration and the Policy key, so it no longer replaces a setting or its
  default with nothing.

The `installed0` value that the MSI writes under the HKCU configuration key is
ignored, as is the `Installer` subkey where later MSIs save their install
options (see [MSI](#msi)).

## Windows Group Policy

The ADMX and ADML templates changed in 1.0.0:

- Every policy now needs a value when it is enabled.
- The namespace is now `SSHCAClient_v1.0.0`, and the revision is 1.2.

The Policy registry key and value names did not change, so settings already
applied keep working.

**Intune** can't import a changed template under a namespace it already has.
Import the new templates as a new template, move your settings to profiles
that use it, then delete the profiles that use the old one and the old
template. The namespace carries the version of the release that last changed
the templates, and release notes say when they change
([ADR 0003](adr/0003-admx-namespace-carries-the-version-of-the-last-template-change.md)).

**In a Central Store**, replace the old files with the new ones. The file
names did not change.

## systemd units

The packaged units are now sandboxed:

- The two system units, `host-ssh-certificate-renewal.service` and
  `user-ssh-krl-refresh.service`, can only write to `/etc/ssh`, where host
  certificates and the user KRL are written. A drop-in that renews keys or
  writes a KRL elsewhere, or whose reload command writes outside `/etc/ssh`,
  needs `ReadWritePaths=` for that directory:

  ```sh
  sudo systemctl edit host-ssh-certificate-renewal.service
  ```

  ```ini
  [Service]
  ReadWritePaths=/srv/ssh
  ```

  The reload command can still use `sudo`, capabilities and runtimes that
  compile code at run time.
- The user unit, `host-ssh-krl-refresh.service`, only restricts system calls
  and address families, as other sandboxing needs unprivileged user
  namespaces, which some systems disable.

## MSI

The 1.0.0 MSI, and every earlier one, does not remember the properties it was
installed with. When you upgrade an install that used a custom `INSTALLDIR`,
or `START_ON_LOGIN=0` or `START_SSH_AGENT=0`, give the same properties again,
or the upgrade installs to the default directory and turns autostart back on
([#235](https://github.com/andrewheberle/ssh-ca-client/issues/235)):

```powershell
msiexec /i ssh-ca-client_1.0.0_windows_amd64.msi INSTALLDIR="D:\Tools\SSH CA\" START_SSH_AGENT=0
```

MSIs after 1.0.0 save these properties under
`HKLM\SOFTWARE\Andrew Heberle\Serverless SSH CA Client\Installer`, and an
upgrade reuses them unless they are given again on the command line. Once a
release after 1.0.0 is installed, later upgrades don't need the properties.
The `Installer` key is not covered by the 1.0 promise.

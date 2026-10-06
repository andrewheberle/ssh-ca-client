## Name

ssh-ca-client - GUI to interact with the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client [options]
```

## Description

Runs as a system tray application that requests, renews and adds user SSH
certificates to the local SSH Agent.

Certificates are renewed in the background using a refresh token from the OIDC
IdP (if available) once less than `--renew` of their validity remains. If a
refresh is not possible, the certificate can be renewed from the tray menu,
which opens a browser for an interactive login. During an interactive login a
local web server is run on the host and port of the configured `redirect_url`.

The users private key, certificate and refresh token are stored in the
operating system keyring and are shared with the CLI
([ssh-ca-client-cli](ssh-ca-client-cli.md)).

## Options

`--add-on-start`
Add current key and certificate (if valid) to SSH agent on start (default true)

`--config <location>`
Location of the configuration that defines global/system config such as the CA
URL, OIDC IdP configuration and CA trust.

On Linux/BSD/Darwin this is the path to a YAML configuration file and the
default is `/etc/serverless-ssh-ca/config.yml`.

On Windows this is the registry hive to load the configuration from, either
`HKLM` (`HKEY_LOCAL_MACHINE`) or `HKCU` (`HKEY_CURRENT_USER`), and the default
is `HKLM`. Any configuration set via Group Policy is applied over this.

`--debug`
Enable debug logging.

`--disable-proxy`
Disable proxying of PuTTY Agent (pageant) requests to the native OpenSSH SSH
Agent (Windows only option).

`--json`
Enable JSON logging (on Windows this flag is only relevant when `--log.file`
is passed).

`--life <duration>`
Lifetime of SSH certificate (default 24h0m0s).

The maximum life configured on the CA cannot be exceeded.

`--log <path>`
Log directory.

The default is `$HOME/.config/serverless-ssh-ca/log` (Linux/BSD/Darwin)
or `%APPDATA%\Serverless SSH CA Client\log` (Windows).

`--log.file`
Log to a file (Windows only option).

By default on Windows logs are sent to the Event Log however this can be
directed to a file inside the configured log directory with this flag.

`--renew <duration>`
Renew once remaining time gets below this value (default 1h0m0s). This cannot
be larger than `--life`.

`--version`
Show version and exit.

## Upgrading

The following changes affect users of previous versions:

* The `--addr` option has been removed. The listen address for the OIDC
  authentication flow is taken from the configured `redirect_url`, which must
  use `http`.
* The `--user` option has been removed. User data is now stored in the
  operating system keyring and is not migrated from the previous user
  configuration file, so after upgrading use the "Generate" menu item to create
  a new private key and then request a new certificate.
* On Windows the configuration is read from the registry (or Group Policy)
  rather than a YAML configuration file.

## ssh-ca-client

Part of the [Serverless SSH CA Client](../README.md)

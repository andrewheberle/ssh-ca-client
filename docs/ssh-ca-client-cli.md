## Name

ssh-ca-client-cli - CLI to interact with the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [options] [subcommand]
```

## Options

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

`--json`
Enable JSON logging.

## User Data

The users SSH private key, certificate and OIDC refresh token (if available) are
stored in the operating system keyring (Windows Credential Manager, macOS
Keychain or a Secret Service provider such as `gnome-keyring` on Linux/BSD).

**Note:** The `--user` and `--keyfile` options from previous versions have been
removed, as user data is no longer stored in a user configuration file.

## Sub-Commands

`generate`
Generate a SSH private key.

See [ssh-ca-client-generate](ssh-ca-client-cli-generate.md)

`host`
Request and renew SSH host certificates.

See [ssh-ca-client-host](ssh-ca-client-cli-host.md)

`krl`
Download or display a SSH key revocation list (KRL).

See [ssh-ca-client-show](ssh-ca-client-cli-krl.md)

`login`
Request user SSH certificates.

See [ssh-ca-client-login](ssh-ca-client-cli-login.md)

`show`
Show user SSH private key, public key and/or certificate.

See [ssh-ca-client-show](ssh-ca-client-cli-show.md)

`version`
Show the current version of the ssh-ca-client-cli

See [ssh-ca-client-show](ssh-ca-client-cli-show.md)

## Name

ssh-ca-client-cli - CLI to interact with the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [options] [subcommand]
```

## Options

`--config <path>`
Path to configuration file the defines global/system config such as the CA URL,
OIDC IdP configuration and CA trust.

The default is `/etc/serverless-ssh-ca/config.yml` (Linux/BSD/Darwin) or
`%PROGRAMDATA%\Serverless SSH CA Client\config.yml` (Windows).

`--debug`
Enable debug logging.

`--user <path>`
The path to store user specific configuration (this is ignored for the `host`)
sub-command.

The default is `$HOME/.config/serverless-ssh-ca/user.yaml` (Linux/BSD/Darwin)
or `%APPDATA%\Serverless SSH CA Client\config.yml` (Windows).

`--keyfile <path>`
This option changes the behaviour of reads/writes to the user configuration
file so that instead of using DPAPI on Windows for protection of sensitive
data and storing the encryption key in the users login keyring on other
platforms, instead a random key is generated and written to the path
specified.

This `keyfile` is then used for encryption/decryption operations of this data.

It is important that this file is protected and if this file is lost any
encrypted data in the user configuration will also be lost.

This option is primarily targted for systems that do not have secret service
available, such as servers.

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

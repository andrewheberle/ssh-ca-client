## Name

ssh-ca-client - GUI to interact with the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client [options]
```

## Options

`--add-on-start`
Add current key and certificate (if valid) to SSH agent on start (default true)

`--addr <address>`
Listen address for OIDC auth flow (default "localhost:3000")

`--config <path>`
Path to configuration file the defines global/system config such as the CA URL,
OIDC IdP configuration and CA trust.

The default is `/etc/serverless-ssh-ca/config.yml` (Linux/BSD/Darwin) or
`%PROGRAMDATA%\Serverless SSH CA Client\config.yml` (Windows).

`--json`
Enable JSON logging (on Windows this flag is only relevant when `--log.file`
is passed).

`--life <duration>`
Lifetime of SSH certificate (default 24h0m0s).

The maximum life configured on the CA cannot be exceeded.

`--log <path>`
Log directory.

`--log.file`
Log to a file (Windows only option).

By default on Windows logs are sent to the Event Log however this can be
directed to a file inside the configured log directory with this flag.

The default is `$HOME/.config/serverless-ssh-ca/log` (Linux/BSD/Darwin)
or `%APPDATA%\Serverless SSH CA Client\log` (Windows).

`--renew <duration>`
Renew once remaining time gets below this value (default 1h0m0s)

`--user <path>`
The path to store user specific configuration sub-command.

The default is `$HOME/.config/serverless-ssh-ca/user.yaml` (Linux/BSD/Darwin)
or `%APPDATA%\Serverless SSH CA Client\config.yml` (Windows).

`--version`
Show version and exit.

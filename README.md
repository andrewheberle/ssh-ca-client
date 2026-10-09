# ssh-ca-client

[![codecov](https://codecov.io/gh/andrewheberle/ssh-ca-client/graph/badge.svg?token=dH7xSBu8eE)](https://codecov.io/gh/andrewheberle/ssh-ca-client)

This provides the client-side service to interact with the [Serverless
Certificate Authority](https://github.com/andrewheberle/serverless-ssh-ca).

## Installing

There are two versions of the client, one CLI based and the other GUI based both of which
are tested on Windows and Linux.

[![Get it from the Snap Store](https://snapcraft.io/en/dark/install.svg)](https://snapcraft.io/ssh-ca-client)

On Linux the client is available from the Snapcraft store, however at this time
there are additional steps required to allow the snap version access to the SSH
authentication agent socket due to it's strict confinement.

An example wrapper script is located under `snap/scripts/wrapper.sh` that uses
`socat` to listen on a socket in your home directory and proxies any access to
the "real" SSH authentication agent socket.

In addition you must manually connect the following interfaces for this snap:

```sh
# allow access to the Gnome Keyring
sudo snap connect ssh-ca-client:password-manager-service
# connect the home interface to allow access to ssh-agent socket in $HOME
sudo snap connect ssh-ca-client:home
# start via wrapper script
path/to/wrapper.sh
```

Alternatively binary releases and a Debian/Ubuntu package for Linux are
available from the GitHub Releases page or you may add the APT repository to
your system as follows:

```sh
curl -fsSL https://packages.hebs.net.au/ssh-ca-client/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/ssh-ca-client.gpg
echo "deb [signed-by=/usr/share/keyrings/ssh-ca-client.gpg] https://packages.hebs.net.au/ssh-ca-client stable main" | sudo tee /etc/apt/sources.list.d/ssh-ca-client.list
sudo apt-get update
sudo apt-get install ssh-ca-client
```

On Windows there is an MSI build that includes both the GUI and CLI versions
and is the recommended option for Windows users.

### Building From Source

#### CLI

```sh
go install github.com/andrewheberle/ssh-ca-client/cmd/ssh-ca-client-cli@latest
```

#### GUI

```sh
go install github.com/andrewheberle/ssh-ca-client/cmd/ssh-ca-client@latest
```

#### MSI

The MSI is built on Linux using `wixl` from [msitools](https://gitlab.gnome.org/GNOME/msitools)
0.106 or later (packaged as `wixl` and `wixl-data` on Debian 13 "trixie").
Build the Windows binaries with GoReleaser first, then the MSI:

```sh
goreleaser release --clean --snapshot --skip sign
templates/build-msi.sh "$(git describe --tags)" dist/ssh-ca-client.msi
```

#### Testing

Unit tests have no external dependencies:

```sh
go test -race ./...
```

End-to-end tests run the client against the published
[Serverless SSH CA](https://www.npmjs.com/package/@andrewheberle/serverless-ssh-ca)
package and require Node.js 24 or later and npm:

```sh
go test -tags e2e -race ./internal/e2e/...
```

The CA is run by its test server,
[@andrewheberle/serverless-ssh-ca-testing](https://www.npmjs.com/package/@andrewheberle/serverless-ssh-ca-testing),
which is released with the CA. The npm dependencies are installed on the first
run, which requires network access. The versions of the CA and test server
that are used are set in
[internal/e2e/testdata/ca/package.json](internal/e2e/testdata/ca/package.json).

By default the CA runs on Node.js using the package's Node.js helpers. Set
`E2E_CA_RUNTIME=workerd` to run it under workerd, the Cloudflare Workers
runtime, with a local D1 database and Secrets Store via the Wrangler test
harness instead:

```sh
E2E_CA_RUNTIME=workerd go test -tags e2e -race ./internal/e2e/...
```

CI runs the tests under both runtimes.

To test against an unreleased version of the CA, set `E2E_CA_PACKAGE` to any
npm install spec, such as a tarball built from a checkout of
[serverless-ssh-ca](https://github.com/andrewheberle/serverless-ssh-ca), and
`E2E_CA_TESTING_PACKAGE` to do the same for the test server. Either can be set
on its own:

```sh
# in serverless-ssh-ca
npm ci && npm run build -w packages/core -w packages/testing && npm pack -w packages/core -w packages/testing

# in ssh-ca-client
E2E_CA_PACKAGE=/path/to/andrewheberle-serverless-ssh-ca-X.Y.Z.tgz \
E2E_CA_TESTING_PACKAGE=/path/to/andrewheberle-serverless-ssh-ca-testing-X.Y.Z.tgz \
go test -tags e2e -race ./internal/e2e/...
```

Relative paths are resolved from `internal/e2e`, so absolute paths are
simplest. The next run without either variable reinstalls the pinned versions.

The CA repository calls the [End-to-end tests](.github/workflows/e2e.yml)
workflow with `ca-ref` and `client-ref` inputs to test its changes against a
client git ref (or `latest`, the latest GitHub release) before publishing.
When `ca-ref` is set, the CA's OpenAPI schema is also checked with
[oasdiff](https://github.com/oasdiff/oasdiff) for changes that would break the
client under test.

#### API Schema

The client's API code in [internal/pkg/api](internal/pkg/api) is generated from
`openapi.json`, which is a copy of the schema shipped in the pinned CA package.
CI fails if they differ, so after changing the CA version update the schema and
regenerate the code:

```sh
npm ci --prefix internal/e2e/testdata/ca
npm run sync-schema --prefix internal/e2e/testdata/ca
```

## Configuration

The client requires the IdP and CA details set as follows:

```yaml
issuer: OIDC Issuer
client_id: OIDC Client ID
scopes: ["openid", "email", "profile"]
redirect_url: http://localhost:3000/auth/callback
ca_url: https://ca.example.com/
trusted_ca: ecdsa-sha2-nistp256 AAAAE2VjZ...
```

On Linux/BSD/Darwin this is a YAML file, by default
`/etc/serverless-ssh-ca/config.yml`, however this may also be overidden using
the `--config` command line flag.

On Windows both the GUI and CLI read their configuration from the registry
under `SOFTWARE\Andrew Heberle\Serverless SSH CA Client`, with `--config`
selecting the hive to use: `HKLM` (the default) or `HKCU`. Any configuration
set via Group Policy is applied over this.

**Note:** Previous versions of the GUI read a YAML configuration file on
Windows. This file is no longer used, so its settings must be moved to the
registry or Group Policy.

The `redirect_url` must use `http` as the client listens on this address during
an interactive login.

If one of the requested scopes is `offline_access` and this is supported by the
OIDC IdP then the client can use the provided refresh token for subsequent
certificate renewals.

On Windows these system level options can be set using Group Policy via the
ADMX/ADML files in the `policy` sub-directory of this repository. These files
are also installed by the MSI into a `policy` sub-directory of the install
location (by default `C:\Program Files\Serverless SSH CA Client\policy`).

The GUI and CLI store persistent user data such as the users private key,
refresh token (if available) and certificate in the operating system keyring
(Windows Credential Manager, macOS Keychain or a Secret Service provider such
as `gnome-keyring` on Linux/BSD). The GUI and CLI share this data, so a key
generated or certificate requested by one is available to the other.

This allows the use of a shared/system configuration that defines the OIDC and
SSH CA configuration with user specific data kept seperate.

### As A Snap

The snap build must be configured as follows:

```sh
sudo snap set ssh-ca-client issuer="OIDC Issuer"
sudo snap set ssh-ca-client client-id="OIDC Client ID"
# This is the default value
sudo snap set ssh-ca-client scopes=openid,email,profile
# This is the default value
sudo snap set ssh-ca-client redirect-url=http://localhost:3000/auth/callback
sudo snap set ssh-ca-client ca-url=https://ca.example.com/
sudo snap set ssh-ca-client trusted-ca="ecdsa-sha2-nistp256 AAAAE2VjZ..."
```

The above commands would generate the same configuration as the YAML example
above.

### Configuration Privacy/Security

Sensitive data such as the users SSH private key and the OIDC refresh token are
stored in the operating system keyring, which protects them using the
platforms own mechanisms. A keyring/secret service must therefore be available
to use the GUI and the `login`, `generate` and `show` sub-commands of the CLI.
The `host` sub-command does not use the keyring.

**Note:** Previous versions stored this data in a user configuration file
(`user.yml`), protected using DPAPI on Windows or a key held in the keyring on
other platforms, and the CLI also supported a `--keyfile` option. This data is
not migrated, so after upgrading generate a new private key (via the GUI
"Generate" menu item or `ssh-ca-client-cli generate`) and request a new
certificate.


## Requirements

Regardless of the version being run there must be a running `ssh-agent` to handle
private keys, certificates and authentication to your SSH client of choice.

On Windows this requires the `OpenSSH Agent` service to be set to `Manual` start
and `ssh-agent.exe` must be started on login for your user.

On Linux `ssh-agent` is often started as part of your normal login process and in
addition the secure storage of sensitive material requires the users `login` keyring
to be unlocked, which is usually the default in most desktop environments.

## Running via the CLI

The client can be run in the following ways:

### User Certificates

#### Generating a private key

To generate a new private key, run as follows:

```sh
ssh-ca-client-cli generate
```

#### Show Existing Key/Public Key/Certificate

```sh
ssh-ca-client-cli show [--private|--certificate [--git]|--public]
```

By default the client only displays the users public key, however the
`--private` and `--certificate` options may be provided. The `--git` option
outputs the certificate in a format suitable for signing git commits.

#### Requesting a Certificate

To request a certificate from the CA, run the client as follows:

```sh
ssh-ca-client-cli login
```

This will trigger an interactive OIDC authentication flow via the users
web browser to obtain an authentication token, which will be used to perform
a request to the CA for a SSH certificate.

If a refresh token was provided by the OIDC IdP, this will be used initially to
attempt a renewal of the authentication token so the process can avoid an
interactive authentication flow.

### Host Certificates

The CLI can be used to request certificates for pre-exisiting SSH host keys using the
`host` sub-command as follows:

```sh
# request certificates
ssh-ca-client-cli host

# renew existing certificates
ssh-ca-client-cli host --renew
```

#### Overview

Requesting host certificates is restricted to users that have been explicitly
allowed to do this in tge configuration of the CA.

By default the CLI will attempt to request certificates for the following keys:

* /etc/ssh/ssh_host_rsa_key
* /etc/ssh/ssh_host_ecdsa_key
* /etc/ssh/ssh_host_ed25519_key

Certificates will be saved as `KEYNAME-cert.pub` and can be used by `sshd` by
adding the following to your `sshd_config` (or `/etc/ssh/sshd_conf.d/*.conf`):

```
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

To ensure your ssh client trusts hosts with certificates issued by your CA you
must add the following to your `authorized_keys` file:

```
@cert-authority *.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdH...
```

The value of `*.example.com` sets what hosts should be trusted when they present
a certificate signed by the specified CA public key (ie the
`ecdsa-sha2-nistp256...` value). It is also possible to have `*` to trust the
CA for all hosts.

By default the CLI will request a certificate with the hostname of the system
you are running the command on, however it is recommeded to include the FQDN
and IP addresses of the host using the `--principals` option as follows:

```sh
ssh-ca-client-cli host --principals hostname,hostname.example.com,192.168.1.1,etc
```

The CA does not currently enforce any restrictions on what principals it will
issue a certificate for at this time.

#### Renewals

If the host possesses a valid (ie unexpired) certificate issued by the CA the
renewal of the certificate can be completed without requiring an interactive
SSO process via OIDC.

The renewed certificate will be issued with identical principals and extensions
as the current certificate with renewals being skipped unless the certificate
has less than 50% of validity left (based on the default of 30-days validity).

Example systemd unit files are located in the `systemd` directory and these are
installed by the DEB package so renewals can be enabled as follows if you have
installed via the package:

```sh
sudo systemctl enable --now host-ssh-certificate-renewal.timer
```

#### Command Line Options

The `host` sub-command supports the following command-line options:

| Flag        | Type       | Default | Description |
|---|---|---|---|
| `--life` | `time.Duration` | 30d | Lifetime of certificate |
| `--delay` | `time.Duration` | 250ms | Delay between requests/renewals for multiple keys (randomised between 50% and 150%) |
| `--key` | `[]string` | /etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_ecdsa_key,/etc/ssh/ssh_host_rsa_key | Key(s) to request/renew certificates for (may be specified multiple times or as a comma seperated string). ECDSA, Ed25519 and RSA (2048 bits or larger) keys are supported |
| `--principals` | `[]string` | `hostname` | Principal(s) to request on certificate (may be specified multiple times or as a comma seperated string) |
| `--renew` | `bool` | false | Attempt to renew existing certificate(s) for the specified key(s) |
| `--force` | `bool` | false | Force renewal of certificate(s) regardless of remaining validity |
| `--renewat` | `float64` | 0.5 | Renew at this fraction of remaining validity for existing certificate(s) |

The `--addr` option from previous versions has been removed as the listen
address for the OIDC auth flow is now taken from the configured `redirect_url`.

#### Example

The following example shows the initial request for SSH host certificates and a subsequent renewal.

This example assumes you are working from your local device and requesting host certificates for a remote system without a web browser, so port 3000 will be forwarded to allow the initial OIDC authentication process to be handled locally:

```sh
# Initially connect to your host and forward port 3000 locally
ssh -L 3000:localhost:3000 admin@remotehost
# Request the initial certificate(s) with three principals (hostname, FQDN and IP address)
ssh-ca-client-cli host --principals remotehost --principals remotehost.example.com,192.168.1.10
# Visit the URL displayed on the console using your local browser (eg http://localhost:3000/auth/login) and authenticate against the IdP
# Some time later perform a renewal
ssh-ca-client-cli host --renew
```

## As a GUI

The GUI supports the following command line flags:

| Flag              | Type            | Description                                                                 |
|-------------------|-----------------|-----------------------------------------------------------------------------|
| `--life`          | `time.Duration` | Lifetime of SSH certificate                                                 |
| `--renew`         | `time.Duration` | Renew once remaining time gets below this value                             |
| `--config`        | `string`        | Configuration file (Linux) or registry hive, `HKLM` or `HKCU` (Windows)     |
| `--log`           | `string`        | Log directory, which contains `tray.log` and `crash.log`                    |
| `--log.file`      | `bool`          | Log to a file instead of the Windows Event Log (Windows only)               |
| `--json`          | `bool`          | Enable JSON logging                                                         |
| `--debug`         | `bool`          | Enable debug logging                                                        |
| `--disable-proxy` | `bool`          | Disable proxying of PuTTY Agent (pageant) requests (Windows only)           |
| `--add-on-start`  | `bool`          | Add current key and certificate (if valid) to SSH agent on start            |
| `--version`       | `bool`          | Show version and exit                                                       |

The defaults are as follows:

| Flag              | Default (Windows)                          | Default (Linux)                        |
|-------------------|--------------------------------------------|----------------------------------------|
| `--life`          | `24h`                                      | `24h`                                  |
| `--renew`         | `1h`                                       | `1h`                                   |
| `--config`        | `HKLM`                                     | `/etc/serverless-ssh-ca/config.yml`    |
| `--log`           | `%LOCALAPPDATA%\Serverless SSH CA Client\log` | `~/.local/state/serverless-ssh-ca/log` |
| `--log.file`      | `false`                                    | n/a (always logs to a file)            |
| `--disable-proxy` | `false`                                    | n/a (always disabled)                  |
| `--add-on-start`  | `true`                                     | `true`                                 |

The `--addr` and `--user` options from previous versions have been removed. The
listen address for the OIDC auth flow is taken from the configured
`redirect_url` and user data is stored in the operating system keyring.

On Linux the default log directory follows `$XDG_STATE_HOME` if set, and when
running as a snap logs are written to `$SNAP_USER_COMMON`. Previous versions
logged to `%APPDATA%\Serverless SSH CA Client\log` (Windows) or
`~/.config/serverless-ssh-ca/log` (Linux), and any logs there are no longer
used.

# Attributions

The icons used by the client are made by Freepik from [www.flaticon.com](https://www.flaticon.com).

## Name

ssh-ca-client-cli-login - Request and renew user SSH certificates from the Serverless SSH CA

## Synopsis

```sh
ssh-ca-client-cli [global options] login [--add]
                                         [--force]
                                         [--life <duration>]
                                         [--skip-agent]
```

## Description

Issues or renews a users SSH certificates using an interactive OIDC
authentication flow for requests with the principals added to the certificate
based on the claims returned from the OIDC IdP.

Renewals may use a refresh token from the OIDC IdP if the configuration of the
IdP allows this.

When an interactive login is required, a local web server is started on the
host and port of the `redirect_url` from the configuration for the duration of
the login and the users browser is opened at its login page. If the browser
cannot be opened, the URL to visit is logged. The login must complete within 5
minutes and may be cancelled with CTRL-C.

**Note:** The `--addr` option from previous versions has been removed as the
listen address is now taken from the `redirect_url`, which must use `http`.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--add`
If an existing certificate exists, attempt to add this certificate to the local
SSH Agent on startup.

`--force`
Force renewal of an existing certificate even if it has more than 50% of its
validity period left.

`--life <duration>`
Request or renew a certificate with the sepecified duration.

The accepted minimum and maximum duration is enforced by the CA and for
renewals the duration may not be larger than the current certificate.

This is a `duration` so may be provided with the following units:

* `ms` - milliseconds
* `s` - seconds
* `h` - hours

The default is `24h`

`--skip-agent`
By default any issued certificate will be added to the local SSH Agent.

Passing `--skip-agent` disables this.

## Examples

* Request/renew a certificate:

  ```sh
  ssh-ca-client-cli login
  ```

* Force renewal of an existing certificate:

  ```sh
  ssh-ca-client-cli login --force
  ```

* Request a certificate with a shorter than default validity period:

  ```sh
  ssh-ca-client-cli login --life 1h
  ```

## Configuration

The following configuration options, specified by the `--config` flag, must be set.

All values are required.

```yaml
# The issuer, client_id, scopes and redirect_url must match your OIDC IdP
issuer: https://idp.example.com/
client_id: OIDC Client ID
scopes: ["openid", "email", "profile", "offline_access"]
# The redirect_url must use http as the client listens on this address during login
redirect_url: http://localhost:3000/auth/callback
# The CA URL must match the route the Worker CA is deployed to
ca_url: https://ca.example.com/
# The SSH public key of the CA, used to validate issued certificates are from the expected CA
trusted_ca: ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgJTsYW+tHl0lz/rnO8djbwq0B3uZ5sGugXU6Ha5S2rTdzMDgit2DO+hoivdT4I07rMrRtmFI179wUY06gIf00=
```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)

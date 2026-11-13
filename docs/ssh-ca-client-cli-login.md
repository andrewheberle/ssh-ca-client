## ssh-ca-client-cli login

Login via OIDC and request a certificate from CA

### Synopsis

Issues a users SSH certificate using an interactive OIDC authentication
flow, with the principals added to the certificate based on the claims returned
from the OIDC IdP.

A new certificate is only requested once half of the current certificate's
lifetime has passed, unless --force is set. If the IdP issued a refresh token
at an earlier login, the new certificate is obtained with that token and no
interactive login is needed (a refresh). Any issued certificate is added to the
local SSH Agent unless --skip-agent is set.

When an interactive login is required, a local web server is started on the
host and port of the redirect_url from the configuration for the duration of
the login and the users browser is opened at its login page. If the browser
cannot be opened, the URL to visit is logged. The login must complete within 5
minutes and may be cancelled with CTRL-C.

The --addr option from previous versions has been removed as the listen address
is now taken from the redirect_url, which must use http.

```
ssh-ca-client-cli login [flags] [args]
```

### Examples

```
# Request a certificate, or a new one if the current one is due
ssh-ca-client-cli login

# Request a new certificate even if the current one is not yet due
ssh-ca-client-cli login --force

# Request a certificate with a shorter than default validity period
ssh-ca-client-cli login --life 1h
```

### Options

```
      --add[=true|false]          Add existing certificate to SSH agent
      --force[=true|false]        Get a new certificate even if the current one has more than 50% of its lifetime left
  -h, --help[=true|false]         help for login
      --life duration             Lifetime of SSH certificate (default 24h0m0s)
      --skip-agent[=true|false]   Skip adding SSH key and certificate to ssh-agent
```

### Options inherited from parent commands

```
      --config string        Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug[=true|false]   Enable debug logging
      --json[=true|false]    Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


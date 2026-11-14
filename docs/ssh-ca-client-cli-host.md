## ssh-ca-client-cli host

Request or renew host certificates

### Synopsis

Issues or renews one or more host SSH certificates with the initial request
requiring an OIDC authentication process against the configured IdP and
subsequent renewals being possible using the current (unexpired) certificate.

When renewing using an existing certificate the principals of the certificate
cannot be changed and the requested lifetime cannot be longer than the current
certificate or the configured maximum of the CA.

When an initial request requires an interactive login, a local web server is
started on the host and port of the redirect_url from the configuration for
the duration of the login. A single login is used for all requested keys.

ECDSA, Ed25519 and RSA (2048 bits or larger) host keys are supported. The --key
and --principals options accept a comma separated list or may be provided more
than once. It is recommended to request the hostname and IP address(es) of the
host as principals so the client can properly verify the host when connecting
via SSH. The default principal is the hostname of the system.

With --renew, a key given with --key must already have a certificate. Without
--key, the default keys that have no certificate are skipped, as a host may
only have certificates for some of them, but the renewal fails if none of them
has one.

As this command writes certificates issued for host SSH keys it needs write
access to the directory holding the SSH host keys, which by default is /etc/ssh,
so this command should be run as root.

A renewal revokes the certificate it replaces. From OpenSSH 9.8 sshd only reads
host certificates when it starts or is reloaded, so until then it keeps
presenting the previous, revoked certificate. The --reload-command option sets
a command, run with /bin/sh -c, that reloads sshd. It is run once, after all
keys have been processed, if any host certificate was written, even if another
key failed or the command was interrupted. A failing reload command makes this
command fail, but the certificates that were written are kept. Without
--reload-command a reminder to reload sshd is logged instead.

This command is not available on Windows or when installed as a snap.

The --addr option from previous versions has been removed as the listen address
is now taken from the redirect_url, which must use http.

```
ssh-ca-client-cli host [flags] [args]
```

### Examples

```
# Request a certificate with three principals
ssh-ca-client-cli host --principals foo,foo.example.com,192.168.1.10

# Request a certificate with a short lifespan period
ssh-ca-client-cli host --life 168h

# Request a certificate for an Ed25519 and ECDSA host key
ssh-ca-client-cli host --key /etc/ssh/ssh_host_ed25519_key --key /etc/ssh/ssh_host_ecdsa_key

# Renew existing certificates
ssh-ca-client-cli host --renew

# Renew existing certificates and reload sshd if any were renewed
ssh-ca-client-cli host --renew --reload-command "systemctl try-reload-or-restart ssh.service"
```

### Options

```
      --delay duration          Delay between requests/renewals (randomised between 50% and 150%, 0 disables) (default 250ms)
      --force[=true|false]      Force renewal even if current certificate has more than 50.0% validity left
  -h, --help[=true|false]       help for host
      --key strings             Path to private key(s) (default [/etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_ecdsa_key,/etc/ssh/ssh_host_rsa_key])
      --life duration           Lifetime of SSH certificate (default 720h0m0s)
      --principals strings      Principals to add to the host certificate request (default [<hostname>])
      --reload-command string   Command run with /bin/sh -c once host certificates have changed, such as to reload sshd
      --renew[=true|false]      Renew existing certificate
      --renew-at float          Renew once this fraction (0 to 1) of the certificate lifetime has passed (default 0.5)
```

### Options inherited from parent commands

```
      --config string        Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug[=true|false]   Enable debug logging
      --json[=true|false]    Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


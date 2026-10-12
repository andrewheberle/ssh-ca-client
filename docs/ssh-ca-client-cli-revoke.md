## ssh-ca-client-cli revoke

Revoke a certificate

### Synopsis

Revoke a user or host certificate at the CA so it is added to the key
revocation list (KRL). Revocation cannot be undone.

By default the current user certificate is revoked. With --host the current
certificates for the host keys set by --key are revoked instead, which needs
read access to the host private keys so should be run as root. Revoking host
certificates is not available on Windows or when installed as a snap.

Revocation uses a proof of possession of the private key the certificate was
issued for, so no login is needed. Once revoked, the certificate is removed
from the SSH agent and deleted, so a new certificate can be requested with
login or host.

The --serial option revokes the certificates with those serial numbers instead
of the current certificate. They must have been issued for the same private key,
so for example a previous certificate that has not yet expired can be revoked.
With --host only a single --key may be given with --serial. Revoking the
current certificate does not revoke any previous certificates for the same key,
so if a private key may have been compromised generate a new key (or new host
keys) as well as revoking its certificates.

The certificates to be revoked are shown and confirmation is asked for unless
--yes is given. Without a terminal, --yes is required.

A certificate is only rejected by ssh or sshd once they use a KRL that
includes it, see the krl command.

Revocation is only available from the command line, not from the system tray
application.

```
ssh-ca-client-cli revoke [flags] [args]
```

### Examples

```
# Revoke the current user certificate
ssh-ca-client-cli revoke

# Revoke a previous user certificate that has not yet expired
ssh-ca-client-cli revoke --serial 12345678901234567890

# Revoke the current host certificates without asking for confirmation
ssh-ca-client-cli revoke --host --yes

# Revoke a previous certificate for the Ed25519 host key
ssh-ca-client-cli revoke --host --key /etc/ssh/ssh_host_ed25519_key --serial 12345678901234567890
```

### Options

```
  -h, --help             help for revoke
      --host             Revoke host certificates instead of the user certificate
      --key strings      Path to host private key(s) whose certificates are revoked with --host (default [/etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_ecdsa_key,/etc/ssh/ssh_host_rsa_key])
      --serial strings   Revoke these certificate serial numbers instead of the current certificate
  -y, --yes              Revoke without asking for confirmation
```

### Options inherited from parent commands

```
      --config string   Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug           Enable debug logging
      --json            Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


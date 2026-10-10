## ssh-ca-client-cli krl

Download and parse a SSH KRL

### Synopsis

Download a key revocation list (KRL) in order to allow ssh or sshd to reject
revoked host or user certificates respectively.

The downloaded KRL is verified against a SSHSIG signature as long as the
trusted_ca option is set in the global/system configuration. Using --force to
write an unverified KRL could allow a third party to provide a malicious KRL
payload in order to prevent legitimate connections.

When --out is an existing KRL, the downloaded KRL is only written if it is not
older than the existing one, comparing the KRL version and then the time it was
generated. This prevents an older KRL being used to un-revoke certificates. If
the existing KRL is newer, for example because it was generated while the CA
clock was wrong, remove the file to replace it.

To have sshd reject users that present a revoked certificate, write the user KRL
to a file and add the following to /etc/ssh/sshd_config:

    RevokedKeys /etc/ssh/revocation_list

To have ssh reject connections to a server with a revoked host certificate,
write the host KRL to a file and add the following to ~/.ssh/config:

    RevokedHostKeys /home/example/.ssh/revocation_list

This command is not available when installed as a snap.

```
ssh-ca-client-cli krl [flags] [args]
```

### Examples

```
# Retrieve the host KRL and verify the signature
ssh-ca-client-cli krl --host

# Write the user KRL to a file for use by sshd
ssh-ca-client-cli krl --out /etc/ssh/revocation_list

# Write the host KRL to a file for use by ssh
ssh-ca-client-cli krl --host --out /home/example/.ssh/revocation_list
```

### Options

```
      --force        Force writing to output even if signature was not verified
  -h, --help         help for krl
      --host         Retrieve host KRL instead of user KRL
  -f, --out string   Output file for KRL
```

### Options inherited from parent commands

```
      --config string   Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug           Enable debug logging
      --json            Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


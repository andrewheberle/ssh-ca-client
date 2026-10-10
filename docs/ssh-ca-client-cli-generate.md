## ssh-ca-client-cli generate

Generate a SSH private key

### Synopsis

Generate a private key or overwrite an existing private key and store the
resulting key in the users keyring. Overwriting a private key also removes any
existing certificate, as it is not valid for the new key.

```
ssh-ca-client-cli generate [flags] [args]
```

### Examples

```
# Generate a new private key overwriting any existing key
ssh-ca-client-cli generate --force

# Show any changes that would be made
ssh-ca-client-cli generate --force --dryrun
```

### Options

```
  -n, --dryrun   Show what would be done
      --force    Force replacing an existing private key
  -h, --help     help for generate
```

### Options inherited from parent commands

```
      --config string   Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug           Enable debug logging
      --json            Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


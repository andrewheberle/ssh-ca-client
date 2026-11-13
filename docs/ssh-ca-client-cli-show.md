## ssh-ca-client-cli show

Show existing private/public key

### Synopsis

Display any existing private key, public key or certificate in OpenSSH format
from the users keyring.

The --git option outputs the current certificate in a format suitable for use
via gpg.ssh.defaultKeyCommand to provide a SSH public key for signing git
commits, and implies --certificate:

    [gpg "ssh"]
      defaultKeyCommand = ssh-ca-client-cli show --git

The --status and --json options from previous versions have been removed.

```
ssh-ca-client-cli show [flags] [args]
```

### Examples

```
# Display the current private key in OpenSSH format
ssh-ca-client-cli show --private

# Display the current certificate in OpenSSH format
ssh-ca-client-cli show --certificate

# Display the current public key
ssh-ca-client-cli show --public
```

### Options

```
      --certificate[=true|false]   Display certificate if one exists
      --git[=true|false]           Output certificate in a format suitable for git signing
  -h, --help[=true|false]          help for show
      --private[=true|false]       Display private key
      --public[=true|false]        Display public key
```

### Options inherited from parent commands

```
      --config string        Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug[=true|false]   Enable debug logging
      --json[=true|false]    Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli](ssh-ca-client-cli.md)	 - A CLI based client for a serverless SSH CA


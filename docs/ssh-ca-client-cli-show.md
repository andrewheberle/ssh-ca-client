## Name

ssh-ca-client-cli-show - Show any existing private key, public key or certificate.

## Synopsis

```sh
ssh-ca-client-cli [global options] show [--certificate [--git]]
                                        [--private]
                                        [--public]
```

## Description

This sub-command can be used to display any exsiting private key, public key or
certificate in Open SSH format from the users keyring.

**Note:** The `--status` and `--json` options from previous versions have been
removed.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--certificate`
Display the current certificate if one exists. When the `--git` flag is used
with this option the current certificate will be output in a format suitable
for use via `gpg.ssh.defaultKeyCommand` to provide a SSH public key for signing
git commits:

The `--git` flag may also be used by itself as it's use implies `--certificate`.

```
[gpg "ssh"]
  defaultKeyCommand = ssh-ca-client-cli show --git
```

`--private`
Display the users private key.

`--public`
Display the users public key.

## Examples

* Display the current private key in Open SSH format:

  ```sh
  ssh-ca-client-cli show --private
  ```

* Display the current certificate in Open SSH format:

  ```sh
  ssh-ca-client-cli show --certificate
  ```

* Display the current public key:

  ```sh
  ssh-ca-client-cli show --public
  ```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)

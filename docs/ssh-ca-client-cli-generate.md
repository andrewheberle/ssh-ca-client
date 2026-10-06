## Name

ssh-ca-client-cli-generate - Generate a user SSH private key

## Synopsis

```sh
ssh-ca-client-cli [global options] generate [--force]
                                            [--dryrun]
```

## Description

Generate a private key or overwrite an existing private key and store the
resulting key in the users keyring. Overwriting a private key also removes any
existing certificate, as it is not valid for the new key.

## Global Options

See [Options](ssh-ca-client-cli.md#options)

## Options

`--force`
Force overwriting an existing private key.

`--dryrun`
`-n`
Show what would occur but make no changes.

## Examples

* Generate a new private key overwriting any existing key:

  ```sh
  ssh-ca-client-cli generate --force
  ```

* Show any changes that would be made:

  ```sh
  ssh-ca-client-cli generate --force --dryrun
  ```

## ssh-ca-client-cli

Part of the [ssh-ca-client-cli](ssh-ca-client-cli.md)

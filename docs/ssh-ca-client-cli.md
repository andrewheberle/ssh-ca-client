## ssh-ca-client-cli

A CLI based client for a serverless SSH CA

### Synopsis

Interacts with the Serverless SSH CA to generate SSH private keys and request,
renew and show user and host SSH certificates.

The --config option sets the location of the configuration that defines
global/system config such as the CA URL, OIDC IdP configuration and CA trust.
On Linux/BSD/Darwin this is the path to a YAML configuration file. On Windows
this is the registry hive to load the configuration from, either HKLM
(HKEY_LOCAL_MACHINE) or HKCU (HKEY_CURRENT_USER), and the default is HKLM. Any
configuration set via Group Policy is applied over this.

The following configuration options must be set:

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

The users SSH private key, certificate and OIDC refresh token (if available)
are stored in the operating system keyring (Windows Credential Manager, macOS
Keychain or a Secret Service provider such as gnome-keyring on Linux/BSD).

The --user and --keyfile options from previous versions have been removed, as
user data is no longer stored in a user configuration file.

```
ssh-ca-client-cli [command] [flags]
```

### Options

```
      --config string   Configuration location (default "/etc/serverless-ssh-ca/config.yml")
      --debug           Enable debug logging
  -h, --help            help for ssh-ca-client-cli
      --json            Enable JSON logging
```

### SEE ALSO

* [ssh-ca-client-cli generate](ssh-ca-client-cli-generate.md)	 - Generate a SSH private key
* [ssh-ca-client-cli host](ssh-ca-client-cli-host.md)	 - Request or renew host certificates
* [ssh-ca-client-cli krl](ssh-ca-client-cli-krl.md)	 - Download and parse a SSH KRL
* [ssh-ca-client-cli login](ssh-ca-client-cli-login.md)	 - Login via OIDC and request a certificate from CA
* [ssh-ca-client-cli revoke](ssh-ca-client-cli-revoke.md)	 - Revoke a certificate
* [ssh-ca-client-cli show](ssh-ca-client-cli-show.md)	 - Show existing private/public key
* [ssh-ca-client-cli version](ssh-ca-client-cli-version.md)	 - Show the current version of the ssh-ca-client-cli


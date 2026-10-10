package cli

// Long descriptions and examples for each command. These are shown by --help
// and are used to generate the markdown documentation in docs/, so are kept
// here to be shared between the snap and non-snap command lists.
//
// Long descriptions are written as plain text that also renders as markdown.

const (
	rootLong = `Interacts with the Serverless SSH CA to generate SSH private keys and request,
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
user data is no longer stored in a user configuration file.`

	generateLong = `Generate a private key or overwrite an existing private key and store the
resulting key in the users keyring. Overwriting a private key also removes any
existing certificate, as it is not valid for the new key.`

	generateExample = `# Generate a new private key overwriting any existing key
ssh-ca-client-cli generate --force

# Show any changes that would be made
ssh-ca-client-cli generate --force --dryrun`

	hostLong = `Issues or renews one or more host SSH certificates with the initial request
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

As this command writes certificates issued for host SSH keys it needs write
access to the directory holding the SSH host keys, which by default is /etc/ssh,
so this command should be run as root.

This command is not available on Windows or when installed as a snap.

The --addr option from previous versions has been removed as the listen address
is now taken from the redirect_url, which must use http.`

	hostExample = `# Request a certificate with three principals
ssh-ca-client-cli host --principals foo,foo.example.com,192.168.1.10

# Request a certificate with a short lifespan period
ssh-ca-client-cli host --life 168h

# Request a certificate for an Ed25519 and ECDSA host key
ssh-ca-client-cli host --key /etc/ssh/ssh_host_ed25519_key --key /etc/ssh/ssh_host_ecdsa_key

# Renew existing certificates
ssh-ca-client-cli host --renew`

	krlLong = `Download a key revocation list (KRL) in order to allow ssh or sshd to reject
revoked host or user certificates respectively.

The downloaded KRL is verified against its SSHSIG signature using the trusted_ca
public key from the configuration, and must only revoke certificates issued by
that CA. A KRL that fails verification is not written. The --force flag is
deprecated and has no effect.

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

This command is not available when installed as a snap.`

	krlExample = `# Retrieve the host KRL and verify the signature
ssh-ca-client-cli krl --host

# Write the user KRL to a file for use by sshd
ssh-ca-client-cli krl --out /etc/ssh/revocation_list

# Write the host KRL to a file for use by ssh
ssh-ca-client-cli krl --host --out /home/example/.ssh/revocation_list`

	loginLong = `Issues or renews a users SSH certificate using an interactive OIDC
authentication flow, with the principals added to the certificate based on the
claims returned from the OIDC IdP.

Renewals may use a refresh token from the OIDC IdP if the configuration of the
IdP allows this. Any issued certificate is added to the local SSH Agent unless
--skip-agent is set.

When an interactive login is required, a local web server is started on the
host and port of the redirect_url from the configuration for the duration of
the login and the users browser is opened at its login page. If the browser
cannot be opened, the URL to visit is logged. The login must complete within 5
minutes and may be cancelled with CTRL-C.

The --addr option from previous versions has been removed as the listen address
is now taken from the redirect_url, which must use http.`

	loginExample = `# Request or renew a certificate
ssh-ca-client-cli login

# Force renewal of an existing certificate
ssh-ca-client-cli login --force

# Request a certificate with a shorter than default validity period
ssh-ca-client-cli login --life 1h`

	revokeLong = `Revoke a user or host certificate.

This command is not yet implemented.`

	showLong = `Display any existing private key, public key or certificate in OpenSSH format
from the users keyring.

The --git option outputs the current certificate in a format suitable for use
via gpg.ssh.defaultKeyCommand to provide a SSH public key for signing git
commits, and implies --certificate:

    [gpg "ssh"]
      defaultKeyCommand = ssh-ca-client-cli show --git

The --status and --json options from previous versions have been removed.`

	showExample = `# Display the current private key in OpenSSH format
ssh-ca-client-cli show --private

# Display the current certificate in OpenSSH format
ssh-ca-client-cli show --certificate

# Display the current public key
ssh-ca-client-cli show --public`

	versionLong = `Display the version of the ssh-ca-client-cli.`

	versionExample = `# Show version
ssh-ca-client-cli version

# Show version as JSON
ssh-ca-client-cli version --json`
)

# Security policy

## Supported versions

Security fixes are made to the latest 1.x release only. Fixes are not
backported to older 1.x releases or to 0.x releases, so upgrade to the latest
release to get them.

| Version        | Supported |
| -------------- | --------- |
| Latest 1.x     | Yes       |
| Older 1.x      | No        |
| 0.x            | No        |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:
[report a vulnerability](https://github.com/andrewheberle/ssh-ca-client/security/advisories/new),
or select **Report a vulnerability** on the repository's **Security** tab.

Do not report vulnerabilities in a public issue, pull request or discussion.

Include as much of the following as you can:

- the version affected, whether you used the CLI or the GUI, and how it was
  installed (deb, snap, MSI or a release archive)
- the operating system, and the keyring and SSH agent in use
- the command, configuration or Group Policy settings involved
- what an attacker can do, and what they need first (for example local
  access as another user, control of the network, or a malicious CA)
- steps to reproduce it, or a proof of concept
- any fix or mitigation you suggest

Don't include real private keys, tokens or certificates. Use ones made for the
report.

You should get a reply within a week. Once the issue is confirmed, the fix is
developed in a private fork for the advisory, released, and then the advisory
is published. You are credited in the advisory unless you ask not to be.

## Scope

This policy covers:

- the CLI, `ssh-ca-client-cli`
- the GUI, `ssh-ca-client`
- the deb, snap and MSI packages, including the systemd units and Windows
  Group Policy templates they install
- the importable Go packages under `pkg/`

Vulnerabilities in the CA, serverless-ssh-ca, are reported to that project
instead, as described in its
[security policy](https://github.com/andrewheberle/serverless-ssh-ca/security/policy).
Vulnerabilities in the operating system keyring, the SSH agent or OpenSSH
itself are reported to those projects, unless the client uses them in a way
that makes them exploitable.

# Values left by old Policy templates are ignored, only in the Policy key

1.0.0 refuses unknown configuration keys, so a misspelt key can't silently leave a setting at its default. The ADMX before v0.26.0 wrote `ClientID`, `RedirectURL`, `CertificateAuthorityURL` and `TrustedCertificateAuthority` to `HKLM\SOFTWARE\Policies\Serverless SSH CA Client`. No release ever read them, as they don't match the configuration keys. Replacing the templates doesn't remove them: a GPO keeps them as "Extra Registry Settings" and applies them again at every refresh, so a machine that still gets them can't start 1.0.0 to 1.0.2, and deleting them locally doesn't last. So the client ignores these four names, lower-cased, in the Policy key only, and logs a warning naming them each time it loads its configuration, until they are removed from the GPO. In the configuration key they are still unknown keys, as only the old templates wrote them and only to the Policy key. The old `Issuer` and `Scopes` lower-case to current names, so they are read as they always have been.

## Considered Options

- **Treat any unknown value in the Policy key as a warning**: also covers leftovers we don't know about. But a value set by hand or by a custom Intune setting can be misspelt as easily as one in the configuration key, and the four names are the only ones any template has written there.
- **Have the MSI delete the old values**: Group Policy writes them back at the next refresh, and the Policy key belongs to Group Policy, not the installer.
- **Document the cleanup only**: every affected machine stays broken until an admin edits the GPO.

## Consequences

The list can't be removed in a 1.x release, as a machine still getting the old values would stop starting. Unknown values are now reported with the registry key they are in, so an admin knows whether to look in the configuration or the GPO.

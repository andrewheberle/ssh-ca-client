# The ADMX namespace carries the version of the release that last changed the templates

Intune won't import a changed ADMX file under a namespace it already has. An admin can only delete every profile that uses the imported template, delete the template, and import the new one, or import the new file under a different namespace. Microsoft recommends putting a version number in the namespace for this ([Import custom ADMX and ADML templates into Intune](https://learn.microsoft.com/intune/device-configuration/settings-catalog/import-custom-admx-templates)).

So the target namespace in `policy/ServerlessSSHCAClient.admx` is `SSHCAClient_v<version>`, where the version is that of the client release that last changed the ADMX or the ADML. It changes whenever either file changes, as Intune imports the two together. `revision` is raised at the same time, in both files, along with `minRequiredRevision`. The Policy registry key and value names never change because of this, so settings already applied keep working, and the namespace is not covered by semver.

## Considered Options

- **A namespace without a version**, such as `AndrewHeberle.Policies.ServerlessSSHCAClient`: one name forever, so a Central Store never shows two categories. But Intune admins would have to delete every profile using the template to update it.
- **A new namespace in every release**: no need to remember when the templates changed, but it would make every release a template update for Intune admins, even when nothing in the templates changed.

## Consequences

A release that changes the templates says so in its release notes. Intune admins then import the new template, move their settings to profiles that use it, and delete the old one. In a Central Store, the new files replace the old ones, as the file names don't change.

`TestPolicyTemplates` checks the form of the namespace and that the revisions agree, but it can't tell whether a change to the templates forgot to change the namespace. That is left to review.

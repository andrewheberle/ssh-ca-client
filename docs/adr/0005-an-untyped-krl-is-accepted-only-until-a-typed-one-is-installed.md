# An untyped KRL is accepted only until a typed one is installed

The CA signs the user and host KRLs with the same key, in the same namespace, and keeps a version counter for each type. Until CA 1.0.2 nothing in the signed bytes said which type a KRL was, so a KRL for one type could be installed as the other. That un-revokes certificates, and then the genuine KRL is refused as older until its counter catches up (#239). Later CAs sign the type into the KRL's comment, as exactly `user` or `host` (andrewheberle/serverless-ssh-ca#629), and the client refuses a KRL that names the other type. A KRL with no comment, as CA 1.0.2 and earlier send, is accepted only while the KRL installed at `--out` has no comment either, or there is none. Once a typed KRL has been installed there, an untyped one can only come from a downgraded CA, or be an old KRL replayed, possibly the other type's, so it is refused and the file is left alone. A KRL already installed at `--out` that names the other type is also refused, as that means two KRLs are being written to one file.

## Considered Options

- **Accept an untyped KRL**: works with every CA, but leaves #239 open for good, even after the CA is upgraded, as anyone able to replace the KRL response can keep replaying an old untyped KRL.
- **Refuse an untyped KRL**: closes #239, but every client stops updating its KRL until its CA is upgraded, which a 1.x release can't require.

## Consequences

A path that has never held a typed KRL is still open to #239, until the CA is upgraded and its first typed KRL is installed. A CA that is downgraded on purpose stops every client updating its KRL until the CA is upgraded again or the installed KRL is removed, which the `krl` command's error says. A CA's version and generation date don't change when it starts naming the type, so the first typed KRL replaces its untyped copy. This can't be loosened again in a 1.x release, as clients would accept replayed KRLs once more.

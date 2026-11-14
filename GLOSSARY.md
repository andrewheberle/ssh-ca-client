# SSH CA Client

The client side of the Serverless SSH Certificate Authority: it keeps SSH keys on users' and hosts' machines and obtains certificates for them from the CA.

## Language

**Trusted CA**:
The certificate authority whose public key the client is configured with; only certificates signed by it are accepted.
_Avoid_: CA key, signing key

**Policy**:
Settings an administrator manages centrally for a Windows machine, applied over its local configuration.
_Avoid_: GPO, override

**Pageant proxy**:
The part of the Windows client that answers PuTTY's agent requests with the keys and certificates held by the OpenSSH agent.
_Avoid_: Pageant process, PuTTY agent bridge

**Snap option**:
A setting an administrator gives the snap with `snap set`; the snap's configuration is generated from them.
_Avoid_: Snap key, snap config

**Certificate store**:
The place one private key and its certificate are kept together, which only ever holds a certificate issued by the Trusted CA for that key.
_Avoid_: Storage, key store, keyring store, file store

**Store backend**:
Where a Certificate store physically keeps its private key and certificate, such as a key file on disk or the system keyring.
_Avoid_: Storage, provider

**User identity**:
A user's SSH private key and current certificate, together with the means to obtain a new certificate for that key after logging in to the identity provider.
_Avoid_: Session, user certificate, account

**Stale certificate**:
A certificate issued by the Trusted CA that has expired but is still held by the SSH agent.
_Avoid_: Old identity, expired identity, leftover key

**Renewal**:
Obtaining a new host certificate for the same key and principals with a **proof of possession** of the key and a current certificate, which the CA revokes in exchange.
_Avoid_: Re-issue

**Refresh**:
Obtaining a new user certificate for the same key without logging in to the identity provider again, using the refresh token it issued at an earlier login.
_Avoid_: Renewal, renew (both are for host certificates)

**Proof of possession**:
A signature made with a key over a timestamp, the key's fingerprint and the request it is sent with, which shows the CA that the client holds that key. It is only valid for that one request, and only briefly (see the CA's [ADR 0006](https://github.com/andrewheberle/serverless-ssh-ca/blob/main/docs/adr/0006-proofs-of-possession-are-bound-to-the-request.md)).
_Avoid_: PoP, proof, signature

**KRL**:
A key revocation list signed by the Trusted CA, listing the revoked certificates of one type (user or host).
_Avoid_: Revocation list, CRL, blocklist

**Rollback**:
Installing a KRL older than the one already in place, which would un-revoke certificates; it is always refused.
_Avoid_: Downgrade

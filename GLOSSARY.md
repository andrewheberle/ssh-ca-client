# SSH CA Client

The client side of the Serverless SSH Certificate Authority: it keeps SSH keys on users' and hosts' machines and obtains certificates for them from the CA.

## Language

**Trusted CA**:
The certificate authority whose public key the client is configured with; only certificates signed by it are accepted.
_Avoid_: CA key, signing key

**Certificate store**:
The place one private key and its certificate are kept together, which only ever holds a certificate issued by the Trusted CA for that key.
_Avoid_: Storage, key store, keyring store, file store

**Store backend**:
Where a Certificate store physically keeps its private key and certificate, such as a key file on disk or the system keyring.
_Avoid_: Storage, provider

**KRL**:
A key revocation list signed by the Trusted CA, listing the revoked certificates of one type (user or host).
_Avoid_: Revocation list, CRL, blocklist

**Rollback**:
Installing a KRL older than the one already in place, which would un-revoke certificates; it is always refused.
_Avoid_: Downgrade

# Secure Components

The Secure Components suite provide mechanisms to easily implement encryption (symmetric or public key), signing, and sharding of messages. They also provide for easy serialization to and from [CBOR](https://cbor.io/), and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md).

## Goals

* Provide a minimal set of datatypes for representing common encryption constructions.
* Provide serialization of types to and from CBOR and UR.
* Base these types on algorithms that are considered best practices.
* Provide common abilities like private and public key encryption and signing, and also innovative constructs like Sharded Secret Key Reconstruction (SSKR).
* Focus on structures of particular use to blockchain and cryptocurrency developers.
* Allow for the future extension of functionality to include additional cryptographic algorithms and methods.
* Provide a reference implementation in Swift that is easy to use and hard to abuse.

## Top-Level Types

The types defined in the Secure Components suite are designed to be minimal, simple to use, and composable. The central "top level" type of Secure Components is `Envelope`, which is a general container for messages that provides for encryption, signing, and sharding. The other types can be used independently, but are often most useful when used in conjunction with `Envelope`.

Many of the types defined herein are assigned CBOR tags for use when encoding these structures. The following types may be used embedded within larger structures as tagged CBOR, or as top-level objects in URs. Note that when encoding URs, a top-level CBOR tag is not used, as the UR type provides that information.

|Type|CBOR Tag|UR Type|
|---|---|---|
|`Envelope`||`crypto-envelope`|
|`Identity`||`crypto-identity`|
|`Message`||`crypto-msg`|
|`Peer`||`crypto-peer`|
|`SealedMessage`||`crypto-sealed`|

## Tagged Types

Types that do not define a UR type generally would never be serialized as a top-level object, but are usually serialized as part of a larger structure.

|Type|CBOR Tag|
|---|---|
|`Digest`|
|`Password`|
|`PrivateAgreementKey`|
|`PublicAgreementKey`|
|`PrivateSigningKey`|
|`PublicSigningKey`|
|`Signature`|
|`SymmetricKey`|

## Untagged Types

A number of types that participate in serialization are simply serialized a CBOR byte strings. They do not need tags because they are used in contexts where their meaning is fixed and unlikely to change over time. These include:

* `AAD`
* `Auth`
* `Ciphertext`
* `Nonce`
* `Plaintext`
* `Salt`

## Algorithms

The algorithms Secure Components currently incorporate are listed here. The components include mechanisms that allow for the future addition of additional algorithms and methods.

* **Hashing:** [Blake2b](https://datatracker.ietf.org/doc/rfc7693)
* **Signing:** [EdDSA-25519](https://datatracker.ietf.org/doc/html/rfc8032)
* **Symmetric Encryption:** [IETF ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
* **Public Key Encryption:** [X25519](https://datatracker.ietf.org/doc/html/rfc7748)
* **Key Derivation**: [HKDF over SHA-512](https://datatracker.ietf.org/doc/html/rfc5869)
* **Password-Based Key Derivation**: [Scrypt](https://datatracker.ietf.org/doc/html/rfc7914)
* **Sharding**: [Sharded Secret Key Reconstruction (SSKR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)

## Examples

This section includes a set of high-level examples of API usage in Swift involving `Envelope`, including example CBOR and UR output.

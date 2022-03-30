# Secure Components - Definitions

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** March 28, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Examples](2-EXAMPLES.md)
* Definitions: This document.

---

## Introduction

This section describes each component, and provides its CDDL definition for CBOR serialization.

## Envelope

`Envelope` is the central "top level" type of Secure Components. It is a general container for messages that provides for encryption, signing, and sharding.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|48|`crypto-msg`|`EncryptedMessage`|
|702||`Permit`|

An `Envelope` allows for flexible signing, encryption, and sharding of messages. Here is its definition in Swift:

```swift
public enum Envelope {
    case plaintext(Data, [Signature])
    case encrypted(EncryptedMessage, Permit)
}
```

It is an enumerated type with two cases: `.plaintext` and `.encrypted`.

* If `.plaintext` is used, it may also carry one or more signatures.
* If `.encrypted` is used, the `EncryptedMessage` is accompanied by a `Permit` that defines the conditions under which the `EncryptedMessage` may be decrypted.

To facilitate further decoding, it is RECOMMENDED that the payload of an `Envelope` should itself be tagged CBOR.

`Envelope` can contain as its payload another CBOR-encoded `Envelope`. This facilitates both sign-then-encrypt and encrypt-then sign constructions.

The reason why `.plaintext` messages may be signed and `.encrypted` messages may not is that generally a signer should have access to the content they are signing, therefore this design encourages the sign-then-encrypt order of operations. If encrypt-then-sign is preferred, then this is easily accomplished by creating an `.encrypted` and then enclosing that envelope in a `.plaintext` with the appropriate signatures.

A `Permit` specifies the conditions under which an `EncryptedMessage` may be decrypted. It is an enumerated type with three cases:

```swift
public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}
```

* `.symmetric` means that the `EncryptedMessage` was encrypted with a `SymmetricKey` that the receiver is already expected to have.
* `.recipients` facilitates multi-recipient public key cryptography by including an array of `SealedMessage`, each of which is encrypted to a particular recipient's public key, and which contains an ephemeral key that can be used by a recipient to decrypt the main message.
* `.share` facilitates social recovery by pairing an `EncryptedMessage` encrypted with an ephemeral key with an `SSKRShare`, and providing for the production of a set of `Envelope`s, each one including a different share. Only an M-of-N threshold of shares will allow the recovery of the ephemeral key and hence the decryption of the original message. Each recipient of one of these `Envelope`s will have an encrypted backup of the entire original `EncryptedMessage`, but only a single `SSKRShare`.

### CDDL for Envelope

```
envelope = #6.48(envelope-plaintext / envelope-encrypted)

envelope-plaintext = [ plaintext-type, payload, signatures ]

envelope-encrypted = [ encrypted-type, permit ]

plaintext-type: uint = 1
encrypted-type: uint = 2
payload: bytes
signatures: [signature]
```

### CDDL for Permit

```
permit = #6.702(permit-symmetric / permit-recipients / permit-sskr)

permit-symmetric = [ permit-symmetric-type ]
permit-recipients = [ permit-recipients-type, recipients ]
permit-sskr [ permit-sskr-type, sskr-share ]

permit-symmetric-type: uint = 1
permit-recipients-type: uint = 2
permit-sskr-type: uint = 3

recipients: [1* sealed-message]
sskr-share: crypto-sskr
```

---

## EncryptedMessage

`EncryptedMessage` is a symmetrically-encrypted message and is specified in full in [BCR-2022-001](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-001-secure-message.md).

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|49|`crypto-envelope`|`Envelope`|

### CDDL for EncryptedMessage

```
crypto-msg = #6.49([ type, ciphertext, aad, nonce, auth ])

type: uint = 1          ; type 1: IETF-ChaCha20-Poly1305
ciphertext: bytes       ; encrypted using ChaCha20
aad: bytes              ; Additional Authenticated Data
nonce: bytes .size 12   ; Random, generated at encryption-time
auth: bytes .size 16    ; Authentication tag created by Poly1305
```

---

## Identity

`Identity` holds key material such as a Seed belonging to an identifiable entity, or an HDKey derived from a Seed. It can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|50|`crypto-identity`|`Identity`|

### Derivations

* `PrivateSigningKey`: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869) with `salt` and `info`: `signing`.
* `PublicSigningKey`: [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) x-only public key.
* `PrivateAgreementKey`: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869) with `salt` and `info`: `agreement`.
* `PrivateSigningKey`: [RFC-7748 X25519](https://datatracker.ietf.org/doc/html/rfc7748).

### CDDL for Identity

```
crypto-identity = #6.50([identity-type, key-material, salt])

identity-type: uint = 1
key-material: bytes
salt: bytes
```

---

## Peer

`Peer` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|51|`crypto-peer`|`Peer`|

### CDDL for Peer

```
crypto-peer = #6.51([peer-type, public-signing-key, public-agreement-key])

peer-type: uint = 1
```

---

## SealedMessage

`SealedMessage` is a message that has been one-way encrypted to a particular `Peer`, and is used to implement multi-recipient public key encryption using `Envelope`. The sender of the message is generated at encryption time, and the ephemeral sender's public key is included, enabling the receipient to decrypt the message without identifying the sender.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|55|`crypto-sealed`|`SealedMessage`|

### CDDL for SealedMessage

```
crypto-sealed = #6.55([sealed-type, crypto-message, ephemeral-public-key])

sealed-type: uint = 1
ephemeral-public-key: public-agreement-key
```

---

## Digest

A Digest is a cryptographic hash of some source data. Currently Secure Components specifies the use of [blake32b](https://datatracker.ietf.org/doc/rfc7693), but more algorithms may be supported in the future.

|CBOR Tag|Swift Type|
|---|---|
|700|`Digest`|

### CDDL for Digest

```
digest = #6.700([digest-type, blake-hash])

digest-type: uint = 1       ; blake32b
blake-hash: bytes .size 32
```

---

## Password

`Password` is a password that has been salted and hashed using [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), and is thereofore suitable for storage and use as a proxy for a user's identity. To validate an entered password, the same hashing algorithm using the same parameters and salt must be performed again, and the hashes compared to determine validity. This way the authenticator never needs to store the password.

|CBOR Tag|Swift Type|
|---|---|
|701|`Password`|

### CDDL for Password

```
password = #6.701([password-type, n, r, p, salt, hashed-password])

password-type: uint = 1             ; scrypt
n: uint                             ; iterations
r: uint                             ; block size
p: uint                             ; parallelism factor
salt: bytes                         ; random salt (16 bytes recommended)
hashed-password: bytes              ; 32 bytes recommended
```

---

## PrivateAgreementKey

A Curve25519 private key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

|CBOR Tag|Swift Type|
|---|---|
|703|`PrivateAgreementKey`|

### CDDL for PrivateAgreementKey

```
private-agreement-key = #6.703([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## PrivateSigningKey

A private key for creating [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.

|CBOR Tag|Swift Type|
|---|---|
|704|`PrivateSigningKey`||700|`Digest`|

### CDDL for PrivateSigningKey

```
private-signing-key = #6.704([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## PublicAgreementKey

A Curve25519 public key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

|CBOR Tag|Swift Type|
|---|---|
|705|`PublicAgreementKey`|

### CDDL for PublicAgreementKey

```
public-agreement-key = #6.705([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## PublicSigningKey

An x-only public key for verifying [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.

|CBOR Tag|Swift Type|
|---|---|
|706|`PublicSigningKey`|

### CDDL for PublicSigningKey

```
public-signing-key = #6.706([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## Signature

A [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signature.

|CBOR Tag|Swift Type|
|---|---|
|707|`Signature`|

### CDDL for Signature

```
signature = #6.707([ signature-type, signature-bytes, signature-tag ])

signature-type: uint = 1
signature-bytes: bytes .size 64
signature-tag: bytes
```

---

## SymmetricKey

A symmetric key for encryption and decryption of [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) messages.
|CBOR Tag|Swift Type|
|---|---|
|708|`SymmetricKey`|

### CDDL for SymmetricKey

```
symmetric-key = #6.708([ symmetric-key-type, key ])

symmetric-key-type: uint = 1
key: bytes .size 32
```

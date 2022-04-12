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

`Envelope` may contain as its payload another CBOR-encoded `Envelope`. This facilitates various constructions, including sign-then-encrypt and encrypt-then sign.

The reason why `.plaintext` messages may be signed and `.encrypted` messages may not is that generally a signer should have access to the content of what they are signing, therefore this design encourages the sign-then-encrypt order of operations. If encrypt-then-sign is preferred, then this is easily accomplished by creating an `.encrypted` and then enclosing that envelope in a `.plaintext` with the appropriate signatures.

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

```mermaid
graph TB
    subgraph EncryptedMessage
        ciphertext
        aad
        nonce
        auth
    end
```

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

## PrivateKeyBase

`PrivateKeyBase` holds key material such as a Seed belonging to an identifiable entity, or an HDKey derived from a Seed. It can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.

```mermaid
graph LR
  subgraph PrivateKeyBase
    key-material;
    salt;
  end
  subgraph PublicKeyBase
    SigningPublicKey;
    AgreementPublicKey;
  end
    key-material --> SigningPrivateKey;
    key-material --> AgreementPrivateKey;
    salt --> AgreementPrivateKey;
    SigningPrivateKey --> SigningPublicKey-Schnorr;
    SigningPrivateKey --> SigningPublicKey-ECDSA;
    AgreementPrivateKey --> AgreementPublicKey;
    SigningPublicKey-Schnorr --> SigningPublicKey;
    SigningPublicKey-ECDSA --> SigningPublicKey;
```

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|50|`crypto-prvkeys`|`PrivateKeyBase`|

### Derivations

* `SigningPrivateKey`: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869) with `salt` and `info`: `signing`.
* `SigningPublicKey`: [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) x-only public key or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) public key.
* `AgreementPrivateKey`: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869) with `salt` and `info`: `agreement`.
* `SigningPrivateKey`: [RFC-7748 X25519](https://datatracker.ietf.org/doc/html/rfc7748).

### CDDL for PrivateKeyBase

```
crypto-prvkeys = #6.50([prvkeys-type, key-material, salt])

prvkeys-type: uint = 1
key-material: bytes
salt: bytes
```

---

## PublicKeyBase

`PublicKeyBase` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption. The `SigningPublicKey` may specifically be for verifying Schnorr or ECDSA signatures.

```mermaid
graph TB
    subgraph PublicKeyBase
        SigningPublicKey
        AgreementPublicKey
    end
```

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|51|`crypto-pubkeys`|`PublicKeyBase`|

### CDDL for PublicKeyBase

```
crypto-pubkeys = #6.51([pubkeys-type, signing-public-key, agreement-public-key])

pubkeys-type: uint = 1
```

---

## SealedMessage

`SealedMessage` is a message that has been one-way encrypted to a particular `PublicKeyBase`, and is used to implement multi-recipient public key encryption using `Envelope`. The sender of the message is generated at encryption time, and the ephemeral sender's public key is included, enabling the receipient to decrypt the message without identifying the sender.

```mermaid
graph TB
    subgraph PublicKeyBase
        EncryptedMessage
        AgreementPublicKey
    end
```

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|55|`crypto-sealed`|`SealedMessage`|

### CDDL for SealedMessage

```
crypto-sealed = #6.55([sealed-type, crypto-message, ephemeral-public-key])

sealed-type: uint = 1
ephemeral-public-key: agreement-public-key
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

`Password` is a password that has been salted and hashed using [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), and is thereofore suitable for storage and use for authenticating users via password. To validate an entered password, the same hashing algorithm using the same parameters and salt must be performed again, and the hashes compared to determine validity. This way the authenticator never needs to store the password. The processor and memory intensive design of the scrypt algorithm makes such hashes resistant to brute-force attacks.

```mermaid
graph TB
    subgraph Password
        n
        r
        p
        salt
        hashed-password
    end
```

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

## AgreementPrivateKey

A Curve25519 private key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

|CBOR Tag|Swift Type|
|---|---|
|703|`AgreementPrivateKey`|

```mermaid
graph TB
    subgraph AgreementPrivateKey
        key
    end
```

### CDDL for AgreementPrivateKey

```
private-agreement-key = #6.703([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## AgreementPublicKey

A Curve25519 public key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

|CBOR Tag|Swift Type|
|---|---|
|704|`AgreementPublicKey`|

```mermaid
graph TB
    subgraph AgreementPublicKey
        key
    end
```

### CDDL for AgreementPublicKey

```
agreement-public-key = #6.704([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## SigningPrivateKey

A private key for creating [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.

|CBOR Tag|Swift Type|
|---|---|
|705|`SigningPrivateKey`||700|`Digest`|

```mermaid
graph TB
    subgraph SigningPrivateKey
        key
    end
```

### CDDL for SigningPrivateKey

```
private-signing-key = #6.705([ key-type, key ])

key-type: uint = 1
key: bytes .size 32
```

---

## SigningPublicKey

A public key for verifying signatures. It has two variants:

* An x-only public key for verifying [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.
* An ECDSA key [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

|CBOR Tag|Swift Type|
|---|---|
|706|`SigningPublicKey`|

```mermaid
graph TB
    subgraph SigningPublicKey-Schnorr
        key-schnorr
    end
    subgraph SigningPublicKey-ECDSA
        key-ecdsa
    end
```

### CDDL for SigningPublicKey

```
signing-public-key = #6.706([ key-variant-schnorr / key-variant-ecdsa ])

key-variant-schnorr = (key-type-schnorr, key-schnorr)
key-type-schnorr: uint = 1
key-schnorr: bytes .size 32

key-variant-ecdsa = (key-type-ecdsa, key-ecdsa)
key-type-ecdsa: uint = 2
key-ecdsa: bytes .size 33
```

### CBOR Diagnostic Notation for SigningPublicKey

* Schnorr variant: `[1, key-schnorr]`
* ECDSA variant: `[2, key-ecdsa]`

---

## Signature

A cryptographic signature. It has two variants:

* A [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signature.
* An ECDSA signature [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

```mermaid
graph TB
    subgraph Signature-Schnorr
        signature-schnorr
        tag
    end
    subgraph Signature-ECDSA
        signature-ecdsa
    end
```

|CBOR Tag|Swift Type|
|---|---|
|707|`Signature`|

### CDDL for Signature

```
signature = #6.707([ signature-variant-schnorr / signature-variant-ecdsa ])

signature-variant-schnorr = (signature-type-schnorr, signature-schnorr, tag)
signature-type-schnorr: uint = 1
signature-schnorr: bytes .size 64
tag: bytes

signature-variant-ecdsa = (signature-type-ecdsa, signature-ecdsa)
signature-type-ecdsa: uint = 2
signature-ecdsa: bytes .size 64
```

---

## SymmetricKey

A symmetric key for encryption and decryption of [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) messages.

```mermaid
graph TB
    subgraph SymmetricKey
        key
    end
```

|CBOR Tag|Swift Type|
|---|---|
|708|`SymmetricKey`|

### CDDL for SymmetricKey

```
symmetric-key = #6.708([ symmetric-key-type, key ])

symmetric-key-type: uint = 1
key: bytes .size 32
```
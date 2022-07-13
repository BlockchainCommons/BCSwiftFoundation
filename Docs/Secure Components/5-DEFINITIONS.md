# Secure Components - Definitions

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** May 16, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Envelope Overview](2-ENVELOPE.md)
* [Envelope Notation](3-ENVELOPE-NOTATION.md)
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md): This document
* [Examples](6-EXAMPLES.md)

---

## Introduction

This section describes each component, and provides its CDDL definition for CBOR serialization.

## Envelope

Please see [here](3-ENVELOPE.md) for a full description.

### Envelope: Swift Definition

For clarity, the Swift definitions here may be slightly simplifed from the reference implementation.

An Envelope consists of a `subject` and a list of zero or more `assertion`s.

```swift
struct Envelope {
    let subject: Subject
    let assertions: [Assertion]
}
```

The `Subject` of an `Envelope` is an enumerated type. `.leaf` represents any terminal CBOR object. `.envelope` represents a nested `Envelope`, `.encrypted` represents an `EncryptedMessage` that could be a `.leaf` or a `.envelope`, and `.redacted` represents a value that has been elided with its place held by its `Digest`.

```swift
enum Subject {
    case leaf(CBOR)
    case envelope(Envelope)
    case encrypted(EncryptedMessage)
    case redacted(Digest)
}
```

An assertion is a `predicate`-`object` pair, each of which is also an `Envelope`.

```swift
struct Assertion {
    let predicate: Envelope
    let object: Envelope
}
```

### Envelope: CDDL

|CBOR Tag|UR Type|Type|
|---|---|---|
|49|`crypto-envelope`|`Envelope`|
|60||`plaintext`|

If the `Envelope` has no assertions, the encoding is simply the `subject`. If the `Envelope` has one or more assertions, then the encoding is an array of two or more elements with the `subject` as the first element, followed by the assertions threaded into the array.

```
envelope = #6.49(
    subject /
    [ subject, ~assertions ]
)
```

The `assertions` are a sequence of one or more `assertion`.

```
assertions = [ 1* assertion ]
```

A subject can be a `envelope` as define above, or one of three other types defined below.

```
subject =
    envelope /
    leaf /
    encrypted /
    redacted
```

A `leaf` is any CBOR-encoded object tagged with #6.60 (`plaintext`).

```
leaf = #6.60(<<any>>)
```

An `encrypted` is a tagged `EncryptedMessage`. The `Digest` of the encrypted plaintext is encoded in the `aad` (additional authenticated data) field of the message.

```
encrypted = crypto-msg
```

A `redacted` is the `Digest` of the redacted item.

```
redacted = digest
```

An `assertion` is a two-element array with the `predicate` as its first element and the `object` as its second. The `predicate` and `object` are `envelope`es as defined above.

```
assertion = [
    predicate,
    object
]

predicate = envelope
object = envelope
```

---

## SCID

A Self-Certifying Identifier (SCID) is a unique 32-byte identifier that, unlike a `Digest` refers to an object or set of objects that may change depending on who resolves the `SCID` or when. In other words, the referent of a `SCID` may be considered mutabled.

### SCID: Swift Defintion

```swift
struct SCID {
    let data: Data
}
```

### SCID: CDDL

```
scid = #6.58(scid-data)

scid-data = bytes .size 32
```

---

## EncryptedMessage

`EncryptedMessage` is a symmetrically-encrypted message and is specified in full in [BCR-2022-001](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-001-secure-message.md).

When used as part of Secure Components, and particularly with `Envelope`, the `aad` field contains the `Digest` of the encrypted plaintext. If non-correlation is necessary, then add random salt to the CBOR plaintext before encrypting.

### EncryptedMessage: Swift Definition

```swift
struct EncryptedMessage {
    let cipherText: Data
    let aad: Data
    let nonce: Data
    let auth: Data
}
```

### EncryptedMessage: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|48|`crypto-msg`|`EncryptedMessage`|

A `crypto-msg` is an array containing either 3 or 4 elements. If additional authenticated data `aad` is non-empty, it is included as the fourth element, and omitted otherwise. `aad` MUST NOT be present and non-empty.

```
crypto-msg = #6.48([ ciphertext, nonce, auth, ? aad ])

ciphertext: bytes       ; encrypted using ChaCha20
aad: bytes              ; Additional Authenticated Data
nonce: bytes .size 12   ; Random, generated at encryption-time
auth: bytes .size 16    ; Authentication tag created by Poly1305
```

---

## PrivateKeyBase

`PrivateKeyBase` holds key material such as a Seed belonging to an identifiable entity, or an HDKey derived from a Seed. It can produce all the private and public keys needed to use this suite. It is usually only serialized for purposes of backup.

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|50|`crypto-prvkeys`|`PrivateKeyBase`|

### PrivateKeyBase: Swift Definition

```swift
struct PrivateKeyBase {
    data: Data
}
```

### PrivateKeyBase: CDDL

```
crypto-prvkeys = #6.50([key-material])

key-material: bytes
```

### Derivations

* `SigningPrivateKey`: [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) with context: `signing`.
* `AgreementPrivateKey`: [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) with context: `agreement`.
* `SigningPublicKey`: [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) x-only public key or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) public key.
* `SigningPrivateKey`: [RFC-7748 X25519](https://datatracker.ietf.org/doc/html/rfc7748).

---

## PublicKeyBase

`PublicKeyBase` holds the public keys of an identifiable entity, and can be made public. It is not simply called a "public key" because it holds at least _two_ public keys: one for signing and another for encryption. The `SigningPublicKey` may specifically be for verifying Schnorr or ECDSA signatures.

### PublicKeyBase: Swift Definition

```swift
struct PublicKeyBase {
    let signingPublicKey: SigningPublicKey
    let agreementPublicKey: AgreementPublicKey
}
```

### PublicKeyBase: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|51|`crypto-pubkeys`|`PublicKeyBase`|

A `crypto-pubkeys` is a two-element array with the first element being the `signing-public-key` and the second being the `agreement-public-key`.

```
crypto-pubkeys = #6.51([signing-public-key, agreement-public-key])
```

---

## SealedMessage

`SealedMessage` is a message that has been one-way encrypted to a particular `PublicKeyBase`, and is used to implement multi-recipient public key encryption using `Envelope`. The sender of the message is generated at encryption time, and the ephemeral sender's public key is included, enabling the receipient to decrypt the message without identifying the real sender.

### SealedMessage: Swift Definition

```swift
struct SealedMessage {
    let message: EncryptedMessage
    let ephemeralPublicKey: AgreementPublicKey
}
```

### SealedMessage: CDDL

|CBOR Tag|UR Type|Swift Type|
|---|---|---|
|55|`crypto-sealed`|`SealedMessage`|

```
crypto-sealed = #6.55([crypto-message, ephemeral-public-key])

ephemeral-public-key: agreement-public-key
```

---

## Digest

A Digest is a cryptographic hash of some source data. Currently Secure Components specifies the use of [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf), but more algorithms may be supported in the future.

|CBOR Tag|Swift Type|
|---|---|
|56|`Digest`|

### CDDL for Digest

```
digest = #6.56(blake3-digest)

blake3-digest: bytes .size 32
```

---

## Password

`Password` is a password that has been salted and hashed using [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), and is thereofore suitable for storage and use for authenticating users via password. To validate an entered password, the same hashing algorithm using the same parameters and salt must be performed again, and the hashes compared to determine validity. This way the authenticator never needs to store the password. The processor and memory intensive design of the scrypt algorithm makes such hashes resistant to brute-force attacks.

### Password: Swift Definition

```swift
struct Password {
    let n: Int
    let r: Int
    let p: Int
    let salt: Data
    let data: Data
}
```

### Password: CDDL

|CBOR Tag|Swift Type|
|---|---|
|701|`Password`|

```
password = #6.701([n, r, p, salt, hashed-password])

n: uint                             ; iterations
r: uint                             ; block size
p: uint                             ; parallelism factor
salt: bytes                         ; random salt (16 bytes recommended)
hashed-password: bytes              ; 32 bytes recommended
```

---

## AgreementPrivateKey

A Curve25519 private key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

### AgreementPrivateKey: Swift Definition

```swift
struct AgreementPrivateKey {
    let data: Data
}
```

### AgreementPrivateKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|702|`AgreementPrivateKey`|

```
agreement-private-key = #6.702(key)

key: bytes .size 32
```

---

## AgreementPublicKey

A Curve25519 public key used for [X25519 key agreement](https://datatracker.ietf.org/doc/html/rfc7748).

### AgreementPublicKey: Swift Definition

```swift
struct AgreementPublicKey {
    let data: Data
}
```

### AgreementPublicKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|62|`AgreementPublicKey`|

```
agreement-public-key = #6.62(key)

key: bytes .size 32
```

---

## SigningPrivateKey

A private key for creating [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) or [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### SigningPrivateKey: Swift Definition

```swift
struct SigningPrivateKey {
    let data: Data
}
```

### SigningPrivateKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|704|`SigningPrivateKey`|

```
private-signing-key = #6.704(key)

key: bytes .size 32
```

---

## SigningPublicKey

A public key for verifying signatures. It has two variants:

* An x-only public key for verifying [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signatures.
* An ECDSA public key [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### SigningPublicKey: Swift Definition

```swift
public enum SigningPublicKey {
    case schnorr(ECXOnlyPublicKey)
    case ecdsa(ECPublicKey)
}
```

### SigningPublicKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|705|`SigningPublicKey`|

A signing public key has two variants: Schnorr or ECDSA. The Schnorr variant is preferred, so it appears as a byte string of length 32. If ECDSA is selected, it appears as a 2-element array where the first element is `1` and the second element is the compressed ECDSA key as a byte string of length 33.

```
signing-public-key = #6.705(key-variant-schnorr / key-variant-ecdsa)

key-variant-schnorr = key-schnorr
key-schnorr: bytes .size 32

key-variant-ecdsa: [1, key-ecdsa]
key-ecdsa: bytes .size 33
```

---

## Signature

A cryptographic signature. It has two variants:

* A [BIP-340 Schnorr](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) signature.
* An ECDSA signature [ECDSA-25519-doublesha256](https://en.bitcoin.it/wiki/BIP_0137) signatures.

### Signature: Swift Definition

```swift
public enum Signature {
    case schnorr(data: Data, tag: Data)
    case ecdsa(data: Data)
}
```

### Signature: CDDL

|CBOR Tag|Swift Type|
|---|---|
|61|`Signature`|

A `signature` has two variants. The Schnorr variant is preferred. Schnorr signatures may include tag data of arbitrary length.

If the `signature-variant-schnorr` is selected and has no tag, it will appear directly as a byte string of length 64. If it includes tag data, it will appear as a two-element array where the first element is the signature and the second element is the tag. The second form MUST NOT be used if the tag data is empty.

If the `signature-variant-ecdsa` is selected, it will appear as a two-element array where the first element is `1` and the second element is a byte string of length 64.

```
signature = #6.61([ signature-variant-schnorr / signature-variant-ecdsa ])

signature-variant-schnorr = signature-schnorr / signature-schnorr-tagged
signature-schnorr: bytes .size 64
signature-schnorr-tagged: [signature-schnorr, schnorr-tag]
schnorr-tag: bytes .size ne 0

signature-variant-ecdsa = [ 1, signature-ecdsa ]
signature-ecdsa: bytes .size 64
```

---

## SymmetricKey

A symmetric key for encryption and decryption of [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) messages.

### SymmetricKey: Swift Definition

```swift
public struct SymmetricKey {
    let data: Data
}
```

### SymmetricKey: CDDL

|CBOR Tag|Swift Type|
|---|---|
|57|`SymmetricKey`|

```
symmetric-key = #6.57( symmetric-key-data )
symmetric-key-data: bytes .size 32
```

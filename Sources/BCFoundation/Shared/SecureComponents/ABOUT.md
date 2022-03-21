# DRAFT: Secure Components

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** March 20, 2022

---

## Introduction

The Secure Components suite provides tools for easily implementing encryption (symmetric or public key), signing, and sharding of messages, including serialization to and from [CBOR](https://cbor.io/), and [UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) formats.

## Status

**DRAFT.** There is a reference implementation in [BCSwiftFoundation](https://github.com/blockchaincommons/BCSwiftFoundation), but everything is still fluid and subject to change.

**⚠️ WARNING:** As of the date of this publication the CBOR tags in the range `48` through `51` and `55` are currently unallocated in the [IANA Registry of CBOR Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml). Blockchain Commons is applying for these number to be assigned to the CBOR specification herein, but because these numbers are in a range that is open to other applications, it may change. For now, these low-numbered tags MUST be understood as provisional and subject to change by all implementors.

## Goals

* Provide a minimal set of datatypes for representing common encryption constructions.
* Provide serialization of types to and from CBOR and UR.
* Base these types on algorithm and constructs that are considered best practices.
* Support innovative constructs like Sharded Secret Key Reconstruction (SSKR).
* Interoperate with structures of particular interest to blockchain and cryptocurrency developers, such as seeds and HD keys.
* Allow for the future extension of functionality to include additional cryptographic algorithms and methods.
* Provide a reference API implementation in Swift that is easy to use and hard to abuse.

## Top-Level Types

The types defined in the Secure Components suite are designed to be minimal, simple to use, and composable. The central "top level" type of Secure Components is `Envelope`, which is a general container for messages that provides for encryption, signing, and sharding. The other types can be used independently, but are often most useful when used in conjunction with `Envelope`.

Many of the types defined herein are assigned CBOR tags for use when encoding these structures. The types in this section may be used embedded within larger structures as tagged CBOR, or as top-level objects in URs. Note that when encoding URs, a top-level CBOR tag is not used, as the UR type provides that information.

|CBOR Tag|UR Type|Type|
|---|---|---|
|48|`crypto-msg`|`Message`|
|49|`crypto-envelope`|`Envelope`|
|50|`crypto-identity`|`Identity`|
|51|`crypto-peer`|`Peer`|
|55|`crypto-sealed`|`SealedMessage`|

## Tagged Types

Types that do not define a UR type generally would never be serialized as a top-level object, but are frequently serialized as part of a larger structure.

|CBOR Tag|Type|
|---|---|
|700|`Digest`|
|701|`Password`|
|702|`Permit`|
|703|`PrivateAgreementKey`|
|704|`PrivateSigningKey`|
|705|`PublicAgreementKey`|
|706|`PublicSigningKey`|
|707|`Signature`|
|708|`SymmetricKey`|

## Untagged Types

A number of types are simply serialized as untagged CBOR byte strings. They do not need tags because they are used in contexts where their meaning is fixed and unlikely to change over time. These include:

* `AAD`
* `Auth`
* `Ciphertext`
* `Nonce`
* `Plaintext`
* `Salt`

## Algorithms

The algorithms that Secure Components currently incorporates are listed below. The components include provisions for the future inclusion of additional algorithms and methods.

* **Hashing:** [Blake2b](https://datatracker.ietf.org/doc/rfc7693)
* **Signing:** [EdDSA-25519](https://datatracker.ietf.org/doc/html/rfc8032)
* **Symmetric Encryption:** [IETF-ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
* **Public Key Encryption:** [X25519](https://datatracker.ietf.org/doc/html/rfc7748)
* **Key Derivation**: [HKDF-SHA-512](https://datatracker.ietf.org/doc/html/rfc5869)
* **Password-Based Key Derivation**: [Scrypt](https://datatracker.ietf.org/doc/html/rfc7914)
* **Sharding**: [SSKR (Sharded Secret Key Reconstruction)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)

## Structure of the Envelope

An `Envelope` allows for flexible signing, encryption, and sharding of messages. Here is its definition in Swift:

```swift
public enum Envelope {
    case plaintext(Data, [Signature])
    case encrypted(Message, Permit)
}
```

It is an enumerated type with two cases: `.plaintext` and `.encrypted`.

* If `.plaintext` is used, it may also carry one or more signatures.
* If `.encrypted` is used, the encrypted `Message` is accompanied by a `Permit` that defines the conditions under which the `Message` may be decrypted.

To facilitate further decoding, it is recommended that the payload of an `Envelope` should itself be tagged CBOR.

`Envelope` can contain as its payload another CBOR-encoded `Envelope`. This facilitates both sign-then-encrypt and encrypt-then sign constructions. The reason why `.plaintext` messages may be signed and `.encrypted` messages may not is that generally a signer should have access to the content of what they are signing, therefore this design encourages the sign-then-encrypt order of operations. If encrypt-then-sign is preferred, then this is easily accomplished by creating an `.encrypted` and then enclosing that envelope in a `.plaintext` with the appropriate signatures.

A `Permit` specifies the conditions under which a `Message` may be decrypted, and contains three cases:

```swift
public enum Permit {
    case symmetric
    case recipients([SealedMessage])
    case share(SSKRShare)
}
```

* `.symmetric` means that the `Message` was encrypted with a `SymmetricKey` that the receiver is already expected to have.
* `.recipients` facilitates multi-recipient public key cryptography by including an array of `SealedMessage`, each of which is encrypted to a particular recipient's public key, and which contains an ephemeral key that can be used by a recipient to decrypt the main message.
* `.share` facilitates social recovery by pairing a `Message` encrypted with an ephemeral key with an `SSKRShare`, and providing for the production of a set of `Envelope`s, each one including a different share. Only an M-of-N threshold of shares will allow the recovery of the ephemeral key and hence the decryption of the original message. Each recipient of one of these `Envelope`s will have an encrypted backup of the entire original `Message`, but only a single `SSKRShare`.

## Examples

This section includes a set of high-level examples of API usage in Swift involving `Envelope`, including example CBOR and UR output (forthcoming). These examples are actual, running unit tests in the [BCSwiftFoundation package](https://github.com/blockchaincommons/BCSwiftFoundation).

### Common structures used by the examples

The unit tests define a common plaintext, and three separate `Identity` objects for *Alice*, *Bob*, and *Carol*, each with a corresponding `Peer`.

```swift
  static let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

  static let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
  static let aliceIdentity = Identity(aliceSeed, salt: "Salt")
  static let alicePeer = Peer(identity: aliceIdentity)

  static let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
  static let bobIdentity = Identity(bobSeed, salt: "Salt")
  static let bobPeer = Peer(identity: bobIdentity)

  static let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
  static let carolIdentity = Identity(carolSeed, salt: "Salt")
  static let carolPeer = Peer(identity: carolIdentity)
```

An `Identity` is derived from source of key material such as a `Seed`, an `HDKey`, or a `Password` that produces key material using the Scrypt algorithm, and also includes a random `Salt`.

An `Identity` is kept secret, and can produce both private and public keys for signing and encryption. A `Peer` is just the public keys and `Salt` extracted from an `Identity` and can be made public. Signing and public key encryption is performed using the `Identity` of one party and the `Peer` from another.

**Note:** Due to the use of randomness in the cryptographic constructions, separate runs of the code are extremly unlike to replicate the exact CBOR and URs (forthcoming) below.

### Example 1: Plaintext

In this example no signing or encryption is performed.

```swift
// Alice sends a plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext)

// Bob reads the message.
XCTAssertEqual(envelope.plaintext, Self.plaintext)
```

### Example 2: Signed Plaintext

```swift
// Alice sends a signed plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)

// Bob receives the message and verifies that it was signed by Alice.
XCTAssertTrue(envelope.hasValidSignature(from: Self.alicePeer))
// Confirm that it wasn't signed by Carol.
XCTAssertFalse(envelope.hasValidSignature(from: Self.carolPeer))

// Bob reads the message.
XCTAssertEqual(envelope.plaintext, Self.plaintext)
```

### Example 3: Multisigned Plaintext

```swift
// Alice and Carol jointly send a signed plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext, signers: [Self.aliceIdentity, Self.carolIdentity])

// Bob receives the message and verifies that it was signed by both Alice and Carol.
XCTAssertTrue(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer]))

// Bob reads the message.
XCTAssertEqual(envelope.plaintext, Self.plaintext)
```

### Example 4: Threshold Multisigned Plaintext

```swift
// Alice sends a signed plaintext message to Bob.
let envelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)

// Bob receives the message and verifies that it was signed by either Alice or Carol.
XCTAssertTrue(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 1))
// Checking for both signatures fails.
XCTAssertFalse(envelope.hasValidSignatures(from: [Self.alicePeer, Self.carolPeer], threshold: 2))

// Bob reads the message.
XCTAssertEqual(envelope.plaintext, Self.plaintext)
```

### Example 5: Symmetric Encryption

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice sends a message encrypted with the key to Bob.
let envelope = Envelope(plaintext: Self.plaintext, key: key)

// Bob decrypts and reads the message.
XCTAssertEqual(envelope.plaintext(with: key), Self.plaintext)

// Can't read with no key.
XCTAssertNil(envelope.plaintext)

// Can't read with incorrect key.
XCTAssertNil(envelope.plaintext(with: SymmetricKey()))
```

### Example 6: Sign-Then-Encrypt

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice signs a plaintext message, then encrypts it.
let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
let envelope = Envelope(inner: innerSignedEnvelope, key: key)

// Bob decrypts the outer envelope using the shared key.
guard
    let innerEnvelope = envelope.inner(with: key)
else {
    XCTFail()
    return
}
// Bob validates Alice's signature.
XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
// Bob reads the message.
XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
```

### Example 7: Encrypt-Then-Sign

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice encrypts a message, then signs it.
let innerEncryptedEnvelope = Envelope(plaintext: Self.plaintext, key: key)
let envelope = Envelope(inner: innerEncryptedEnvelope, signer: Self.aliceIdentity)

// Bob checks the signature of the outer envelope, then decrypts the inner envelope.
guard
    envelope.hasValidSignature(from: Self.alicePeer),
    let plaintext = envelope.inner?.plaintext(with: key)
else {
    XCTFail()
    return
}

// Bob reads the message.
XCTAssertEqual(plaintext, Self.plaintext)
```

### Example 8: Multi-Recipient Encryption

```swift
// Alice encrypts a message so that it can only be decrypted by Bob or Carol.
let envelope = Envelope(plaintext: Self.plaintext, recipients: [Self.bobPeer, Self.carolPeer])

// Bob decrypts and reads the message.
XCTAssertEqual(envelope.plaintext(for: Self.bobIdentity), Self.plaintext)

// Carol decrypts and reads the message.
XCTAssertEqual(envelope.plaintext(for: Self.carolIdentity), Self.plaintext)

// Alice didn't encrypt it to herself, so she can't read it.
XCTAssertNil(envelope.plaintext(for: Self.aliceIdentity))
```

### Example 9: Signed Multi-Recipient Encryption

```swift
// Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
let innerSignedEnvelope = Envelope(plaintext: Self.plaintext, signer: Self.aliceIdentity)
let envelope = Envelope(inner: innerSignedEnvelope, recipients: [Self.bobPeer, Self.carolPeer])

// Bob decrypts the outer envelope using his identity.
guard
    let innerEnvelope = envelope.inner(for: Self.bobIdentity)
else {
    XCTFail()
    return
}
// Bob validates Alice's signature.
XCTAssertTrue(innerEnvelope.hasValidSignature(from: Self.alicePeer))
// Bob reads the message.
XCTAssertEqual(innerEnvelope.plaintext, Self.plaintext)
```

### Example 10: Sharding a Secret using SSKR

```swift
// Dan has a cryptographic seed he wants to backup using a social recovery scheme.
// The seed includes metadata he wants to back up with the key, making it too large
// to fit into a basic SSKR share.
var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
danSeed.name = "Dark Purple Aqua Love"
danSeed.creationDate = try! Date("2021-02-24T00:00:00Z", strategy: .iso8601)
danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

// Dan splits the seed into a single group 2-of-3. This returns an array of arrays
// of Envelope, the outer arrays representing SSKR groups and the inner array
// elements each holding the encrypted seed and a single share.
let envelopes = Envelope.split(plaintext: danSeed.taggedCBOR, groupThreshold: 1, groups: [(2, 3)])

// Flattening the array of arrays gives just a single array of all the envelopes to be distributed.
let sentEnvelopes = envelopes.flatMap { $0 }

// Dan sends one envelope to each of Alice, Bob, and Carol.

// let aliceEnvelope = sentEnvelopes[0] // UNRECOVERED
let bobEnvelope = sentEnvelopes[1]
let carolEnvelope = sentEnvelopes[2]

// At some future point, Dan retrieves two of the three envelopes so he can recover his seed.
let recoveredEnvelopes = [bobEnvelope, carolEnvelope]
let recoveredSeed = try Seed(taggedCBOR: Envelope.plaintext(from: recoveredEnvelopes)!)

// The recovered seed is correct.
XCTAssertEqual(danSeed.data, recoveredSeed.data)
XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
XCTAssertEqual(danSeed.name, recoveredSeed.name)
XCTAssertEqual(danSeed.note, recoveredSeed.note)

// Attempting to recover with only one of the envelopes won't work.
XCTAssertNil(Envelope.plaintext(from: [bobEnvelope]))
```

## Definitions of the Components

Forthcoming. This section will contain detailed descriptions of each component, and its CDDL definition for CBOR serialization.

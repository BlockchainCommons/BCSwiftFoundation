# Secure Components - Examples

**Authors:** Wolf McNally, Christopher Allen, Blockchain Commons</br>
**Revised:** May 16, 2022</br>
**Status:** DRAFT

---

## Contents

* [Overview](1-OVERVIEW.md)
* [Envelope Overview](2-ENVELOPE.md)
* [Envelope Notation](3-ENVELOPE-NOTATION.md)
* [Envelope Expressions](4-ENVELOPE-EXPRESSIONS.md)
* [Definitions](5-DEFINITIONS.md)
* [Examples](6-EXAMPLES.md): This document

---

## Introduction

This section includes a set of high-level examples of API usage in Swift involving `Envelope`.

## Status

These examples are actual, running unit tests in the [BCSwiftFoundation package](https://github.com/blockchaincommons/BCSwiftFoundation). The document and implementation as a whole are considered a draft.

## Common structures used by the examples

The unit tests define a common plaintext, and `SCID`s and `PrivateKeyBase` objects for *Alice*, *Bob*, *Carol*, *ExampleLedger*, and *The State of Example*, each with a corresponding `PublicKeyBase`.

```swift
fileprivate let plaintext = "Hello."

fileprivate let aliceIdentifier = SCID(‡"d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")!
fileprivate let alicePrivateKeys = PrivateKeyBase(Seed(data: ‡"82f32c855d3d542256180810797e0073")!)
fileprivate let alicePublicKeys = alicePrivateKeys.publicKeys

fileprivate let bobIdentifier = SCID(‡"24b5b23d8aed462c5a3c02cc4972315eb71a6c5fdfc0063de28603f467ae499c")!
fileprivate let bobPrivateKeys = PrivateKeyBase(Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!)
fileprivate let bobPublicKeys = bobPrivateKeys.publicKeys

fileprivate let carolIdentifier = SCID(‡"06c777262faedf49a443277474c1c08531efcff4c58e9cb3b04f7fc1c0e6d60d")!
fileprivate let carolPrivateKeys = PrivateKeyBase(Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!)
fileprivate let carolPublicKeys = carolPrivateKeys.publicKeys

fileprivate let exampleLedgerIdentifier = SCID(‡"0eda5ce79a2b5619e387f490861a2e7211559029b3b369cf98fb749bd3ba9a5d")!
fileprivate let exampleLedgerPrivateKeys = PrivateKeyBase(Seed(data: ‡"d6737ab34e4e8bb05b6ac035f9fba81a")!)
fileprivate let exampleLedgerPublicKeys = exampleLedgerPrivateKeys.publicKeys

fileprivate let stateIdentifier = SCID(‡"04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!
fileprivate let statePrivateKeys = PrivateKeyBase(Seed(data: ‡"3e9271f46cdb85a3b584e7220b976918")!)
fileprivate let statePublicKeys = statePrivateKeys.publicKeys
```

A `PrivateKeyBase` is derived from a source of key material such as a `Seed`, an `HDKey`, or a `Password` that produces key material using the Scrypt algorithm, and also includes a random `Salt`.

A `PrivateKeyBase` is kept secret, and can produce both private and public keys for signing and encryption. A `PublicKeyBase` is just the public keys and `Salt` extracted from a `PrivateKeyBase` and can be made public. Signing and public key encryption is performed using the `PrivateKeyBase` of one party and the `PublicKeyBase` from another.

**Note:** Due to the use of randomness in the cryptographic constructions, separate runs of the code are extremly unlikely to replicate the exact CBOR or URs.

## Example 1: Plaintext

In this example no signing or encryption is performed.

```swift
// Alice sends a plaintext message to Bob.
let container = Envelope(plaintext)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob

// Bob receives the container and reads the message.
let receivedPlaintext = try Envelope(ur: ur)
    .extract(String.self)
XCTAssertEqual(receivedPlaintext, plaintext)
```

### Envelope Notation

```
"Hello."
```

## Example 2: Signed Plaintext

```swift
// Alice sends a signed plaintext message to Bob.
let container = Envelope(plaintext)
    .sign(with: alicePrivateKeys)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob

// Bob receives the container.
let receivedContainer = try Envelope(ur: ur)

// Bob receives the message, validates Alice's signature, and reads the message.
let receivedPlaintext = try receivedContainer.validateSignature(from: alicePublicKeys)
    .extract(String.self)
XCTAssertEqual(receivedPlaintext, plaintext)

// Confirm that it wasn't signed by Carol.
XCTAssertThrowsError(try receivedContainer.validateSignature(from: carolPublicKeys))

// Confirm that it was signed by Alice OR Carol.
try receivedContainer.verifySignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 1)

// Confirm that it was not signed by Alice AND Carol.
XCTAssertThrowsError(try receivedContainer.verifySignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 2))
```

### Envelope Notation

```
"Hello." [
    verifiedBy: Signature
]
```

## Example 3: Multisigned Plaintext

```swift
// Alice and Carol jointly send a signed plaintext message to Bob.
let container = Envelope(plaintext)
    .sign(with: [alicePrivateKeys, carolPrivateKeys])
let ur = container.ur

// Alice & Carol ➡️ ☁️ ➡️ Bob

// Bob receives the container and verifies the message was signed by both Alice and Carol.
let receivedPlaintext = try Envelope(ur: ur)
    .verifySignatures(from: [alicePublicKeys, carolPublicKeys])
    .extract(String.self)

// Bob reads the message.
XCTAssertEqual(receivedPlaintext, plaintext)
```

### Envelope Notation

```
"Hello." [
    verifiedBy: Signature
    verifiedBy: Signature
]
```

## Example 4: Symmetric Encryption

```swift
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let container = try Envelope(plaintext)
            .encrypt(with: key)
        let ur = container.ur

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container.
        let receivedContainer = try Envelope(ur: ur)

        // Bob decrypts and reads the message.
        let receivedPlaintext = try receivedContainer
            .decrypt(with: key)
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintext)

        // Can't read with no key.
        try XCTAssertThrowsError(receivedContainer.extract(String.self))

        // Can't read with incorrect key.
        try XCTAssertThrowsError(receivedContainer.decrypt(with: SymmetricKey()))
```

### Envelope Notation

```
EncryptedMessage
```

## Example 5: Sign-Then-Encrypt

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice signs a plaintext message, then encrypts it.
let container = try Envelope(plaintext)
    .sign(with: alicePrivateKeys)
    .enclose()
    .encrypt(with: key)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob

// Bob receives the container, decrypts it using the shared key, and then validates Alice's signature.
let receivedPlaintext = try Envelope(ur: ur)
    .decrypt(with: key)
    .extract()
    .validateSignature(from: alicePublicKeys)
    .extract(String.self)
// Bob reads the message.
XCTAssertEqual(receivedPlaintext, plaintext)
```

### Envelope Notation

```
EncryptedMessage
```

## Example 6: Encrypt-Then-Sign

It doesn't actually matter whether the `encrypt` or `sign` method comes first, as the `encrypt` method transforms the `subject` into its `.encrypted` form, which carries a `Digest` of the plaintext `subject`, while the `sign` method only adds an `Assertion` with the signature of the hash as the `object` of the `Assertion`.

Similarly, the `decrypt` method used below can come before or after the `validateSignature` method, as `validateSignature` checks the signature against the `subject`'s hash, which is explicitly present when the subject is in `.encrypted` form and can be calculated when the subject is in `.plaintext` form. The `decrypt` method transforms the subject from its `.encrypted` case to its `.plaintext` case, and also checks that the decrypted plaintext has the same hash as the one associated with the `.encrypted` subject.

The end result is the same: the `subject` is encrypted and the signature can be checked before or after decryption.

The main difference between this order of operations and the sign-then-encrypt order of operations is that with sign-then-encrypt, the decryption *must* be performed first before the presence of signatures can be known or checked. With this order of operations, the presence of signatures is known before decryption, and may be checked before or after decryption.

```swift
// Alice and Bob have agreed to use this key.
let key = SymmetricKey()

// Alice encryptes a plaintext message, then signs it.
let container = try Envelope(plaintext)
    .encrypt(with: key)
    .sign(with: alicePrivateKeys)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob

// Bob receives the container, validates Alice's signature, then decrypts the message.
let receivedPlaintext = try Envelope(ur: ur)
    .validateSignature(from: alicePublicKeys)
    .decrypt(with: key)
    .extract(String.self)
// Bob reads the message.
XCTAssertEqual(receivedPlaintext, plaintext)
```

### Envelope Notation

```
EncryptedMessage [
    verifiedBy: Signature
]
```

## Example 7: Multi-Recipient Encryption

```swift
// Alice encrypts a message so that it can only be decrypted by Bob or Carol.
let contentKey = SymmetricKey()
let container = try Envelope(plaintext)
    .encrypt(with: contentKey)
    .addRecipient(bobPublicKeys, contentKey: contentKey)
    .addRecipient(carolPublicKeys, contentKey: contentKey)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob
// Alice ➡️ ☁️ ➡️ Carol

// The container is received
let receivedContainer = try Envelope(ur: ur)

// Bob decrypts and reads the message
let bobReceivedPlaintext = try receivedContainer
    .decrypt(to: bobPrivateKeys)
    .extract(String.self)
XCTAssertEqual(bobReceivedPlaintext, plaintext)

// Alice decrypts and reads the message
let carolReceivedPlaintext = try receivedContainer
    .decrypt(to: carolPrivateKeys)
    .extract(String.self)
XCTAssertEqual(carolReceivedPlaintext, plaintext)

// Alice didn't encrypt it to herself, so she can't read it.
XCTAssertThrowsError(try receivedContainer.decrypt(to: alicePrivateKeys))
```

### Envelope Notation

```
EncryptedMessage [
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

## Example 8: Signed Multi-Recipient Encryption

```swift
// Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
let contentKey = SymmetricKey()
let container = try Envelope(plaintext)
    .sign(with: alicePrivateKeys)
    // .enclose() // Add if you want to encrypt the signature
    .encrypt(with: contentKey)
    .addRecipient(bobPublicKeys, contentKey: contentKey)
    .addRecipient(carolPublicKeys, contentKey: contentKey)
let ur = container.ur

// Alice ➡️ ☁️ ➡️ Bob
// Alice ➡️ ☁️ ➡️ Carol

// The container is received
let receivedContainer = try Envelope(ur: ur)

// Bob validates Alice's signature, then decrypts and reads the message
let bobReceivedPlaintext = try receivedContainer
    .validateSignature(from: alicePublicKeys)
    .decrypt(to: bobPrivateKeys)
    .extract(String.self)
XCTAssertEqual(bobReceivedPlaintext, plaintext)

// Carol validates Alice's signature, then decrypts and reads the message
let carolReceivedPlaintext = try receivedContainer
    .validateSignature(from: alicePublicKeys)
    .decrypt(to: carolPrivateKeys)
    .extract(String.self)
XCTAssertEqual(carolReceivedPlaintext, plaintext)

// Alice didn't encrypt it to herself, so she can't read it.
XCTAssertThrowsError(try receivedContainer.decrypt(to: alicePrivateKeys))
```

### Envelope Notation

```
EncryptedMessage [
    verifiedBy: Signature
    hasRecipient: SealedMessage
    hasRecipient: SealedMessage
]
```

## Example 9: Sharding a Secret using SSKR

```swift
// Dan has a cryptographic seed he wants to backup using a social recovery scheme.
// The seed includes metadata he wants to back up also, making it too large to fit
// into a basic SSKR share.
var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
danSeed.name = "Dark Purple Aqua Love"
danSeed.creationDate = try! Date(iso8601: "2021-02-24")
danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

// Dan encrypts the seed and then splits the content key into a single group
// 2-of-3. This returns an array of arrays of Envelope, the outer arrays
// representing SSKR groups and the inner array elements each holding the encrypted
// seed and a single share.
let contentKey = SymmetricKey()
let containers = try Envelope(danSeed)
    .encrypt(with: contentKey)
    .split(groupThreshold: 1, groups: [(2, 3)], contentKey: contentKey)

// Flattening the array of arrays gives just a single array of all the containers
// to be distributed.
let sentContainers = containers.flatMap { $0 }
let sentURs = sentContainers.map { $0.ur }

// Dan ➡️ ☁️ ➡️ Alice
// Dan ➡️ ☁️ ➡️ Bob
// Dan ➡️ ☁️ ➡️ Carol

// let aliceContainer = Envelope(ur: sentURs[0]) // UNRECOVERED
let bobContainer = try Envelope(ur: sentURs[1])
let carolContainer = try Envelope(ur: sentURs[2])

// At some future point, Dan retrieves two of the three containers so he can recover his seed.
let recoveredContainers = [bobContainer, carolContainer]
let recoveredSeed = try Envelope(shares: recoveredContainers)
    .extract(Seed.self)

// The recovered seed is correct.
XCTAssertEqual(danSeed.data, recoveredSeed.data)
XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
XCTAssertEqual(danSeed.name, recoveredSeed.name)
XCTAssertEqual(danSeed.note, recoveredSeed.note)

// Attempting to recover with only one of the containers won't work.
XCTAssertThrowsError(try Envelope(shares: [bobContainer]))
```

### Envelope Notation

```
EncryptedMessage [
    sskrShare: SSKRShare
]
```

## Example 10: Complex Metadata

```swift
// Assertions made about an SCID are considered part of a distributed set. Which
// assertions are returned depends on who resolves the SCID and when it is
// resolved. In other words, the referent of an SCID is mutable.
let author = Envelope(SCID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
    .add(.dereferenceVia, "LibraryOfCongress")
    .add(.hasName, "Ayn Rand")

// Assertions made on a literal value are considered part of the same set of
// assertions made on the digest of that value.
let name_en = Envelope("Atlas Shrugged")
    .add(.language, "en")

let name_es = Envelope("La rebelión de Atlas")
    .add(.language, "es")

let work = Envelope(SCID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
    .add(.isA, "novel")
    .add("isbn", "9780451191144")
    .add("author", author)
    .add(.dereferenceVia, "LibraryOfCongress")
    .add(.hasName, name_en)
    .add(.hasName, name_es)

let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."

// Assertions made on a digest are considered associated with that specific binary
// object and no other. In other words, the referent of a Digest is immutable.
let bookMetadata = Envelope(Digest(bookData))
    .add("work", work)
    .add("format", "EPUB")
    .add(.dereferenceVia, "IPFS")
```

### Envelope Notation

```
Digest(886d35d99ded5e20c61868e57af2f112700b73f1778d48284b0e078503d00ac1) [
    "format": "EPUB"
    "work": SCID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
        "author": SCID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
            dereferenceVia: "LibraryOfCongress"
            hasName: "Ayn Rand"
        ]
        "isbn": "9780451191144"
        dereferenceVia: "LibraryOfCongress"
        hasName: "Atlas Shrugged" [
            language: "en"
        ]
        hasName: "La rebelión de Atlas" [
            language: "es"
        ]
        isA: "novel"
    ]
    dereferenceVia: "IPFS"
]
```

## Example 11: Self-Certifying Identifier

An analogue of a DID document, which identifies a self-sovereign entity. The document itself can be referred to by its SCID, while the signed document can be referred to by its digest.

```swift
let aliceUnsignedDocument = Envelope(aliceIdentifier)
    .add(.controller, aliceIdentifier)
    .add(.publicKeys, alicePublicKeys)

let aliceSignedDocument = aliceUnsignedDocument
    .enclose()
    .sign(with: alicePrivateKeys, note: "Made by Alice.")
```

### Envelope Notation

```
{
    SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
        controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
        publicKeys: PublicKeyBase
    ]
} [
    verifiedBy: Signature [
        note: "Made by Alice."
    ]
]
```

Signatures have a random component, so anything with a signature will have a non-deterministic digest. Therefore, the two results of signing the same object twice with the same private key will not compare as equal. This means that each signing is a particular event that can never be repeated.

```swift
let aliceSignedDocument2 = aliceUnsignedDocument
    .enclose()
    .sign(with: alicePrivateKeys, note: "Made by Alice.")

XCTAssertNotEqual(aliceSignedDocument, aliceSignedDocument2)
```

```swift
// ➡️ ☁️ ➡️

// A registrar checks the signature on Alice's submitted identifier document,
// performs any other necessary validity checks, and then extracts her SCID from
// it.
let aliceSCID = try aliceSignedDocument.validateSignature(from: alicePublicKeys)
    .extract()
    // other validity checks here
    .extract(SCID.self)

// The registrar creates its own registration document using Alice's SCID as the
// subject, incorporating Alice's signed document, and adding its own signature.
let aliceURL = URL(string: "https://exampleledger.com/scid/\(aliceSCID.data.hex)")!
let aliceRegistration = Envelope(aliceSCID)
    .add(.entity, aliceSignedDocument)
    .add(.dereferenceVia, aliceURL)
    .enclose()
    .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
```

### Envelope Notation

```
{
    SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
        dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
        entity: {
            SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                publicKeys: PublicKeyBase
            ]
        } [
            verifiedBy: Signature [
                note: "Made by Alice."
            ]
        ]
    ]
} [
    verifiedBy: Signature [
        note: "Made by ExampleLedger."
    ]
]
```

```swift
// Alice receives the registration document back, validates its signature, and
// extracts the URI that now points to her record.
let aliceURI = try aliceRegistration
    .validateSignature(from: exampleLedgerPublicKeys)
    .extract()
    .extract(predicate: .dereferenceVia, URL.self)
XCTAssertEqual(aliceURI†, "https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

// Alice wants to introduce herself to Bob, so Bob needs to know she controls her
// identifier. Bob sends a challenge:
let aliceChallenge = Envelope(Nonce())
    .add(.note, "Challenge to Alice from Bob.")
```

### Envelope Notation

```
Nonce [
    note: "Challenge to Alice from Bob."
]
```

```swift
// Alice responds by adding her registered URI to the nonce, and signing it.
let aliceChallengeResponse = aliceChallenge
    .enclose()
    .add(.dereferenceVia, aliceURI)
    .enclose()
    .sign(with: alicePrivateKeys, note: "Made by Alice.")
```

### Envelope Notation

```
{
    {
        Nonce [
            note: "Challenge to Alice from Bob."
        ]
    } [
        dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
    ]
} [
    verifiedBy: Signature [
        note: "Made by Alice."
    ]
]
```

```swift
// Bob receives Alice's response, and first checks that the nonce is the once he sent.
let responseNonce = try aliceChallengeResponse
    .extract()
    .extract()
XCTAssertEqual(aliceChallenge, responseNonce)

// Bob then extracts Alice's registered URI
let responseURI = try aliceChallengeResponse
    .extract()
    .extract(predicate: .dereferenceVia, URL.self)
XCTAssertEqual(responseURI.absoluteString, "https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")

// Bob uses the URI to ask ExampleLedger for Alice's identifier document, then
// checks ExampleLedgers's signature. Bob trusts ExampleLedger's validation of
// Alice's original document, so doesn't bother to check it for internal
// consistency, and instead goes ahead and extracts Alice's public keys from it.
let aliceDocumentPublicKeys = try aliceRegistration
    .validateSignature(from: exampleLedgerPublicKeys)
    .extract()
    .extract(predicate: .entity)
    .extract()
    .extract(predicate: .publicKeys, PublicKeyBase.self)

// Finally, Bob uses Alice's public keys to validate the challenge he sent her.
try aliceChallengeResponse.validateSignature(from: aliceDocumentPublicKeys)
```

## Example 12: Verifiable Credential

```swift
// John Smith's identifier
let johnSmithIdentifier = SCID(‡"78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc")!

// A photo of John Smith
let johnSmithImage = Envelope(Digest("John Smith smiling"))
    .add(.note, "This is an image of John Smith.")
    .add(.dereferenceVia, "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54")

// John Smith's Permanent Resident Card issued by the State of Example
let johnSmithResidentCard = try Envelope(SCID(‡"174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8")!)
    .add(.isA, "credential")
    .add("dateIssued", Date(iso8601: "2022-04-27"))
    .add(.issuer, Envelope(stateIdentifier)
        .add(.note, "Issued by the State of Example")
        .add(.dereferenceVia, URL(string: "https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8")!)
    )
    .add(.holder, Envelope(johnSmithIdentifier)
        .add(.isA, "Person")
        .add(.isA, "Permanent Resident")
        .add("givenName", "JOHN")
        .add("familyName", "SMITH")
        .add("sex", "MALE")
        .add("birthDate", Date(iso8601: "1974-02-18"))
        .add("image", johnSmithImage)
        .add("lprCategory", "C09")
        .add("lprNumber", "999-999-999")
        .add("birthCountry", Envelope("bs").add(.note, "The Bahamas"))
        .add("residentSince", Date(iso8601: "2018-01-07"))
    )
    .add(.note, "The State of Example recognizes JOHN SMITH as a Permanent Resident.")
    .enclose()
    .sign(with: statePrivateKeys, note: "Made by the State of Example.")

// Validate the state's signature
try johnSmithResidentCard.validateSignature(from: statePublicKeys)
```

### Envelope Notation

```
{
    SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        "dateIssued": 2022-04-27
        holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            "birthCountry": "bs" [
                note: "The Bahamas"
            ]
            "birthDate": 1974-02-18
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54) [
                dereferenceVia: "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54"
                note: "This is an image of John Smith."
            ]
            "lprCategory": "C09"
            "lprNumber": "999-999-999"
            "residentSince": 2018-01-07
            "sex": "MALE"
            isA: "Permanent Resident"
            isA: "Person"
        ]
        isA: "credential"
        issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
        note: "The State of Example recognizes JOHN SMITH as a Permanent Resident."
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

```swift
// John wishes to identify himself to a third party using his government-issued
// credential, but does not wish to reveal more than his name, his photo, and the
// fact that the state has verified his identity.

// Redaction is performed by building a set of `Digest`s that will be revealed. All
// digests not present in the reveal-set will be replaced with redaction markers
// containing only the hash of what has been redacted, thus preserving the hash
// tree including revealed signatures. If a higher-level object is redacted, then
// everything it contains will also be redacted, so if a deeper object is to be
// revealed, all of its parent objects also need to be revealed, even though not
// everything *about* the parent objects must be revealed.

// Start a reveal-set
var revealSet: Set<Digest> = []

// Reveal the card. Without this, everything about the card would be redacted.
let top = johnSmithResidentCard
revealSet.insert(top)

// Reveal everything about the state's signature on the card
try revealSet.insert(top.assertion(predicate: .verifiedBy).deepDigests)

// Reveal the top level subject of the card. This is John Smith's SCID.
let topContent = top.subject.envelope!
revealSet.insert(topContent.shallowDigests)

// Reveal everything about the `isA` and `issuer` assertions at the top level of the card.
try revealSet.insert(topContent.assertion(predicate: .isA).deepDigests)
try revealSet.insert(topContent.assertion(predicate: .issuer).deepDigests)

// Reveal the `holder` assertion on the card, but not any of its sub-assertions.
let holder = try topContent.assertion(predicate: .holder)
revealSet.insert(holder.shallowDigests)

// Within the `holder` assertion, reveal everything about just the `givenName`, `familyName`, and `image` assertions.
try revealSet.insert(holder.assertion(predicate: "givenName").deepDigests)
try revealSet.insert(holder.assertion(predicate: "familyName").deepDigests)
try revealSet.insert(holder.assertion(predicate: "image").deepDigests)

// Perform the redaction
let redactedCredential = top.redact(revealing: revealSet)

// Verify that the redacted credential compares equal to the original credential.
XCTAssertEqual(redactedCredential, johnSmithResidentCard)

// Verify that the state's signature on the redacted card is still valid.
try redactedCredential.validateSignature(from: statePublicKeys)
```

### Envelope Notation for Redacted Credential

```
{
    SCID(174842eac3fb44d7f626e4d79b7e107fd293c55629f6d622b81ed407770302c8) [
        REDACTED: REDACTED
        REDACTED: REDACTED
        holder: SCID(78bc30004776a3905bccb9b8a032cf722ceaf0bbfb1a49eaf3185fab5808cadc) [
            "familyName": "SMITH"
            "givenName": "JOHN"
            "image": Digest(4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54) [
                dereferenceVia: "https://exampleledger.com/digest/4d55aabd82301eaa2d6b0a96c00c93e5535e82967f057fd1c99bee94ffcdad54"
                note: "This is an image of John Smith."
            ]
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
            REDACTED: REDACTED
        ]
        isA: "credential"
        issuer: SCID(04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8) [
            dereferenceVia: URI(https://exampleledger.com/scid/04363d5ff99733bc0f1577baba440af1cf344ad9e454fad9d128c00fef6505e8)
            note: "Issued by the State of Example"
        ]
    ]
} [
    verifiedBy: Signature [
        note: "Made by the State of Example."
    ]
]
```

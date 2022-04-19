import XCTest
@testable import BCFoundation
import WolfBase

fileprivate let plaintext = "Hello."

fileprivate let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
fileprivate let alicePrivateKeys = PrivateKeyBase(aliceSeed, salt: "Salt")
fileprivate let alicePublicKeys = alicePrivateKeys.pubkeys

fileprivate let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
fileprivate let bobPrivateKeys = PrivateKeyBase(bobSeed, salt: "Salt")
fileprivate let bobPublicKeys = bobPrivateKeys.pubkeys

fileprivate let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
fileprivate let carolPrivateKeys = PrivateKeyBase(carolSeed, salt: "Salt")
fileprivate let carolPublicKeys = carolPrivateKeys.pubkeys

fileprivate let exampleLedgerSeed = Seed(data: ‡"d6737ab34e4e8bb05b6ac035f9fba81a")!
fileprivate let exampleLedgerPrivateKeys = PrivateKeyBase(exampleLedgerSeed, salt: "Salt")
fileprivate let exampleLedgerPublicKeys = exampleLedgerPrivateKeys.pubkeys

class SimplexTests: XCTestCase {
    func testPredicate() {
        let container = Simplex(predicate: .authenticatedBy)
        XCTAssertEqual(container.format, "authenticatedBy")
    }

    func testNestingPlaintext() {
        let container = Simplex("Hello")
        
        let expectedFormat =
        """
        "Hello"
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testNestingOnce() {
        let container = Simplex("Hello")
            .enclose()
        
        let expectedFormat =
        """
        {
            "Hello"
        }
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testNestingTwice() {
        let container = Simplex("Hello")
            .enclose()
            .enclose()
        
        let expectedFormat =
        """
        {
            {
                "Hello"
            }
        }
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testNestingSigned() {
        let container = Simplex("Hello")
            .sign(with: alicePrivateKeys)
        
        let expectedFormat =
        """
        "Hello" [
            authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testNestingEncloseThenSign() {
        let container = Simplex("Hello")
            .enclose()
            .sign(with: alicePrivateKeys)
        
        let expectedFormat =
        """
        {
            "Hello"
        } [
            authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testNestingSignThenEnclose() {
        let container = Simplex("Hello")
            .sign(with: alicePrivateKeys)
            .enclose()
        
        let expectedFormat =
        """
        {
            "Hello" [
                authenticatedBy: Signature
            ]
        }
        """
        XCTAssertEqual(container.format, expectedFormat)
    }

    func testAssertionsOnAllPartsOfContainer() throws {
        let predicate = Simplex("predicate")
            .add("predicate-predicate", "predicate-object")
        let object = Simplex("object")
            .add("object-predicate", "object-object")
        let container = Simplex("subject")
            .add(predicate, object)
        
        let expectedFormat =
        """
        "subject" [
            "predicate" [
                "predicate-predicate": "predicate-object"
            ]
            : "object" [
                "object-predicate": "object-object"
            ]
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)
    }

    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let container = Simplex(plaintext)
        let ur = container.ur
        
//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(ur)

        let expectedFormat =
        """
        "Hello."
        """
        XCTAssertEqual(container.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container and reads the message.
        let receivedPlaintext = try Simplex(ur: ur)
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintext)
    }

    func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let container = Simplex(plaintext)
            .sign(with: alicePrivateKeys)
        let ur = container.ur

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        let expectedFormat =
        """
        "Hello." [
            authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)
        
        // Bob receives the message, validates Alice's signature, and reads the message.
        let receivedPlaintext = try receivedContainer.validateSignature(from: alicePublicKeys)
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintext)

        // Confirm that it wasn't signed by Carol.
        XCTAssertThrowsError(try receivedContainer.validateSignature(from: carolPublicKeys))
        
        // Confirm that it was signed by Alice OR Carol.
        try receivedContainer.validateSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 1)
        
        // Confirm that it was not signed by Alice AND Carol.
        XCTAssertThrowsError(try receivedContainer.validateSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 2))
    }
    
    func testMultisignedPlaintext() throws {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let container = Simplex(plaintext)
            .sign(with: [alicePrivateKeys, carolPrivateKeys])
        let ur = container.ur

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        let expectedFormat =
        """
        "Hello." [
            authenticatedBy: Signature
            authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

        // Alice & Carol ➡️ ☁️ ➡️ Bob

        // Bob receives the container and verifies the message was signed by both Alice and Carol.
        let receivedPlaintext = try Simplex(ur: ur)
            .validateSignatures(from: [alicePublicKeys, carolPublicKeys])
            .extract(String.self)

        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintext)
    }
    
    func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let container = try Simplex(plaintext)
            .encrypt(with: key)
        let ur = container.ur

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        let expectedFormat =
        """
        EncryptedMessage
        """
        XCTAssertEqual(container.format, expectedFormat)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)
        
        // Bob decrypts and reads the message.
        let receivedPlaintext = try receivedContainer
            .decrypt(with: key)
            .extract(String.self)
        XCTAssertEqual(receivedPlaintext, plaintext)

        // Can't read with no key.
        try XCTAssertThrowsError(receivedContainer.extract(String.self))
        
        // Can't read with incorrect key.
        try XCTAssertThrowsError(receivedContainer.decrypt(with: SymmetricKey()))
    }
    
    func testEncryptDecrypt() throws {
        let key = SymmetricKey()
        let plaintextContainer = Simplex(plaintext)
        print(plaintextContainer.format)
        let encryptedContainer = try plaintextContainer.encrypt(with: key)
        print(encryptedContainer.format)
        XCTAssertEqual(plaintextContainer, encryptedContainer)
        let plaintextContainer2 = try encryptedContainer.decrypt(with: key)
        print(plaintextContainer2.format)
        XCTAssertEqual(encryptedContainer, plaintextContainer2)
    }
    
    func testSignThenEncrypt() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice signs a plaintext message, then encrypts it.
        let container = try Simplex(plaintext)
            .sign(with: alicePrivateKeys)
            .enclose()
            .encrypt(with: key)
        let ur = container.ur
        
        let expectedFormat =
        """
        EncryptedMessage
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container, decrypts it using the shared key, and then validates Alice's signature.
        let receivedPlaintext = try Simplex(ur: ur)
            .decrypt(with: key)
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintext)
    }
    
    func testEncryptThenSign() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice encryptes a plaintext message, then signs it.
        //
        // It doesn't actually matter whether the `encrypt` or `sign` method comes first,
        // as the `encrypt` method transforms the `subject` into its `.encrypted` form,
        // which carries a `Digest` of the plaintext `subject`, while the `sign` method
        // only adds an `Assertion` with the signature of the hash as the `object` of the
        // `Assertion`.
        //
        // Similarly, the `decrypt` method used below can come before or after the
        // `validateSignature` method, as `validateSignature` checks the signature against
        // the `subject`'s hash, which is explicitly present when the subject is in
        // `.encrypted` form and can be calculated when the subject is in `.plaintext`
        // form. The `decrypt` method transforms the subject from its `.encrypted` case to
        // its `.plaintext` case, and also checks that the decrypted plaintext has the same
        // hash as the one associated with the `.encrypted` subject.
        //
        // The end result is the same: the `subject` is encrypted and the signature can be
        // checked before or after decryption.
        //
        // The main difference between this order of operations and the sign-then-encrypt
        // order of operations is that with sign-then-encrypt, the decryption *must*
        // be performed first before the presence of signatures can be known or checked.
        // With this order of operations, the presence of signatures is known before
        // decryption, and may be checked before or after decryption.
        let container = try Simplex(plaintext)
            .encrypt(with: key)
            .sign(with: alicePrivateKeys)
        let ur = container.ur

        let expectedFormat =
        """
        EncryptedMessage [
            authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // Alice ➡️ ☁️ ➡️ Bob

        // Bob receives the container, validates Alice's signature, then decrypts the message.
        let receivedPlaintext = try Simplex(ur: ur)
            .validateSignature(from: alicePublicKeys)
            .decrypt(with: key)
            .extract(String.self)
        // Bob reads the message.
        XCTAssertEqual(receivedPlaintext, plaintext)
    }
    
    func testMultiRecipient() throws {
        // Alice encrypts a message so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let container = try Simplex(plaintext)
            .encrypt(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
        let ur = container.ur

        let expectedFormat =
        """
        EncryptedMessage [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The container is received
        let receivedContainer = try Simplex(ur: ur)
        
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
    }
    
    func testVisibleSignatureMultiRecipient() throws {
        // Alice signs a message, and then encrypts it so that it can only be decrypted by Bob or Carol.
        let contentKey = SymmetricKey()
        let container = try Simplex(plaintext)
            .sign(with: alicePrivateKeys)
            .encrypt(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
        let ur = container.ur
        
        let expectedFormat =
        """
        EncryptedMessage [
            authenticatedBy: Signature
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The container is received
        let receivedContainer = try Simplex(ur: ur)

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
    }
    
    func testHiddenSignatureMultiRecipient() throws {
        // Alice signs a message, and then encloses it in another container before encrypting it so that it can only be decrypted by Bob or Carol. This hides Alice's signature, and requires recipients to decrypt the subject before they are able to validate the signature.
        let contentKey = SymmetricKey()
        let container = try Simplex(plaintext)
            .sign(with: alicePrivateKeys)
            .enclose()
            .encrypt(with: contentKey)
            .addRecipient(bobPublicKeys, contentKey: contentKey)
            .addRecipient(carolPublicKeys, contentKey: contentKey)
        let ur = container.ur
        
        let expectedFormat =
        """
        EncryptedMessage [
            hasRecipient: SealedMessage
            hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // Alice ➡️ ☁️ ➡️ Bob
        // Alice ➡️ ☁️ ➡️ Carol

        // The container is received
        let receivedContainer = try Simplex(ur: ur)

        // Bob decrypts the container, then extracts the inner container and validates Alice's signature, then reads the message
        let bobReceivedPlaintext = try receivedContainer
            .decrypt(to: bobPrivateKeys)
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
        XCTAssertEqual(bobReceivedPlaintext, plaintext)

        // Carol decrypts the container, then extracts the inner container and validates Alice's signature, then reads the message
        let carolReceivedPlaintext = try receivedContainer
            .decrypt(to: carolPrivateKeys)
            .extract()
            .validateSignature(from: alicePublicKeys)
            .extract(String.self)
        XCTAssertEqual(carolReceivedPlaintext, plaintext)

        // Alice didn't encrypt it to herself, so she can't read it.
        XCTAssertThrowsError(try receivedContainer.decrypt(to: alicePrivateKeys))
    }
    
    func testSSKR() throws {
        // Dan has a cryptographic seed he wants to backup using a social recovery scheme.
        // The seed includes metadata he wants to back up also, making it too large to fit
        // into a basic SSKR share.
        var danSeed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        danSeed.name = "Dark Purple Aqua Love"
        danSeed.creationDate = try! Date("2021-02-24T00:00:00Z", strategy: .iso8601)
        danSeed.note = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        // Dan encrypts the seed and then splits the content key into a single group
        // 2-of-3. This returns an array of arrays of Simplex, the outer arrays
        // representing SSKR groups and the inner array elements each holding the encrypted
        // seed and a single share.
        let contentKey = SymmetricKey()
        let containers = try Simplex(danSeed)
            .encrypt(with: contentKey)
            .split(groupThreshold: 1, groups: [(2, 3)], contentKey: contentKey)
        
        // Flattening the array of arrays gives just a single array of all the containers
        // to be distributed.
        let sentContainers = containers.flatMap { $0 }
        let sentURs = sentContainers.map { $0.ur }

        let expectedFormat =
        """
        EncryptedMessage [
            sskrShare: SSKRShare
        ]
        """
        XCTAssertEqual(sentContainers[0].format, expectedFormat)
        
        // Dan sends one container to each of Alice, Bob, and Carol.

//        print(sentContainers[0].taggedCBOR.diag)
//        print(sentContainers[0].taggedCBOR.dump)
//        print(sentContainers[0].ur)

        // Dan ➡️ ☁️ ➡️ Alice
        // Dan ➡️ ☁️ ➡️ Bob
        // Dan ➡️ ☁️ ➡️ Carol

        // let aliceEnvelope = Envelope(ur: sentURs[0]) // UNRECOVERED
        let bobContainer = try Simplex(ur: sentURs[1])
        let carolContainer = try Simplex(ur: sentURs[2])

        // At some future point, Dan retrieves two of the three containers so he can recover his seed.
        let recoveredContainers = [bobContainer, carolContainer]
        let recoveredSeed = try Simplex(shares: recoveredContainers)
            .extract(Seed.self)

        // The recovered seed is correct.
        XCTAssertEqual(danSeed.data, recoveredSeed.data)
        XCTAssertEqual(danSeed.creationDate, recoveredSeed.creationDate)
        XCTAssertEqual(danSeed.name, recoveredSeed.name)
        XCTAssertEqual(danSeed.note, recoveredSeed.note)

        // Attempting to recover with only one of the envelopes won't work.
        XCTAssertThrowsError(try Simplex(shares: [bobContainer]))
    }

    func testComplexMetadata() throws {
        // Assertions made about an SCID are considered part of a distributed set. Which assertions are returned depends on who resolves the SCID and when it is resolved. In other words, the referent of an SCID is mutable.
        let author = Simplex(SCID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, "Ayn Rand")
        
        // Assertions made on a literal value are considered part of the same set of assertions made on the digest of that value.
        let name_en = Simplex("Atlas Shrugged")
            .add(.language, "en")

        let name_es = Simplex("La rebelión de Atlas")
            .add(.language, "es")
        
        let work = Simplex(SCID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .add(.isA, "novel")
            .add("isbn", "9780451191144")
            .add("author", author)
            .add(.dereferenceVia, "LibraryOfCongress")
            .add(.hasName, name_en)
            .add(.hasName, name_es)

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        // Assertions made on a digest are considered associated with that specific binary object and no other. In other words, the referent of a Digest is immutable.
        let bookMetadata = Simplex(Digest(bookData))
            .add("work", work)
            .add("format", "EPUB")
            .add(.dereferenceVia, "IPFS")
        
        let expectedFormat =
        """
        Digest(886d35d99ded5e20c61868e57af2f112700b73f1778d48284b0e078503d00ac1) [
            "format": "EPUB"
            "work": {
                SCID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
                    "author": {
                        SCID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
                            dereferenceVia: "LibraryOfCongress"
                            hasName: "Ayn Rand"
                        ]
                    }
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
            }
            dereferenceVia: "IPFS"
        ]
        """
        XCTAssertEqual(bookMetadata.format, expectedFormat)
    }
    
    func testIdentifier() throws {
        // An analogue of a DID document, which identifies a self-sovereign entity. The
        // document itself can be referred to by its SCID, while the signed document
        // can be referred to by its digest.
        
        let aliceIdentifier = SCID(‡"d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")!
        let aliceUnsignedDocument = Simplex(aliceIdentifier)
            .add(.controller, aliceIdentifier)
            .add(.publicKeys, alicePublicKeys)
        
        let aliceSignedDocument = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let expectedFormat =
        """
        {
            SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                publicKeys: PublicKeyBase
            ]
        } [
            authenticatedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceSignedDocument.format, expectedFormat)
        
        // Signatures have a random component, so anything with a signature will have a
        // non-deterministic digest. Therefore, the two results of signing the same object
        // twice with the same private key will not compare as equal. This means that each
        // signing is a particular event that can never be repeated.

        let aliceSignedDocument2 = aliceUnsignedDocument
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")

        XCTAssertNotEqual(aliceSignedDocument, aliceSignedDocument2)
        
        // ➡️ ☁️ ➡️

        // A registrar checks the signature on Alice's submitted identifier document,
        // performs any other necessary validity checks, and then extracts her SCID from
        // it.
        let aliceSCID = try aliceSignedDocument.validateSignature(from: alicePublicKeys)
            .extract()
            // other validity checks here
            .extract(SCID.self)
        
        // The registrar creates its own registration document using Alice's SCID as the subject, incorporating Alice's signed document, and adding its own signature.
        let aliceURL = URL(string: "https://exampleledger.com/scid/\(aliceSCID.rawValue.hex)")!
        let aliceRegistration = Simplex(aliceSCID)
            .add(.entity, aliceSignedDocument)
            .add(.dereferenceVia, aliceURL)
            .enclose()
            .sign(with: exampleLedgerPrivateKeys, note: "Made by ExampleLedger.")
        
        let expectedRegistrationFormat =
        """
        {
            SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                entity: {
                    SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f) [
                        controller: SCID(d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
                        publicKeys: PublicKeyBase
                    ]
                } [
                    authenticatedBy: Signature [
                        note: "Made by Alice."
                    ]
                ]
            ]
        } [
            authenticatedBy: Signature [
                note: "Made by ExampleLedger."
            ]
        ]
        """
        XCTAssertEqual(aliceRegistration.format, expectedRegistrationFormat)
        
        // Alice receives the registration document back, validates its signature, and extracts the URI that now points to her record.
        let aliceURI = try aliceRegistration
            .validateSignature(from: exampleLedgerPublicKeys)
            .extract()
            .extract(predicate: .dereferenceVia, URL.self)
        XCTAssertEqual(aliceURI†, "https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f")
        
        // Alice wants to introduce herself to Bob, so Bob needs to know she controls her identifier. Bob sends a challenge:
        let aliceChallenge = Simplex(Nonce())
            .add(.note, "Challenge to Alice from Bob.")
        
        let aliceChallengeExpectedFormat =
        """
        Nonce [
            note: "Challenge to Alice from Bob."
        ]
        """
        XCTAssertEqual(aliceChallenge.format, aliceChallengeExpectedFormat)

        // Alice responds by adding her registered URI to the nonce, and signing it.
        let aliceChallengeResponse = aliceChallenge
            .enclose()
            .add(.dereferenceVia, aliceURI)
            .enclose()
            .sign(with: alicePrivateKeys, note: "Made by Alice.")
        
        let aliceChallengeResponseExpectedFormat =
        """
        {
            {
                Nonce [
                    note: "Challenge to Alice from Bob."
                ]
            } [
                dereferenceVia: URI(https://exampleledger.com/scid/d44c5e0afd353f47b02f58a5a3a29d9a2efa6298692f896cd2923268599a0d0f)
            ]
        } [
            authenticatedBy: Signature [
                note: "Made by Alice."
            ]
        ]
        """
        XCTAssertEqual(aliceChallengeResponse.format, aliceChallengeResponseExpectedFormat)

        // Bob receive's Alice's response, and first checks that the nonce is the once he sent.
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
    }
}

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

class SimplexTests: XCTestCase {
    func testPredicate() {
        let container = Simplex(predicate: .authenticatedBy)
        XCTAssertEqual(container.format, "authenticatedBy")
    }
    
    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let container = Simplex(plaintext)
        let ur = container.ur
        
//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(ur)

        XCTAssertEqual(container.format, #""Hello.""#)

        // ➡️ ☁️ ➡️

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

        // ➡️ ☁️ ➡️

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)
        // Bob receives the message and verifies that it was signed by Alice.
        try XCTAssertTrue(receivedContainer.hasValidSignature(from: alicePublicKeys))
        // Confirm that it wasn't signed by Carol.
        try XCTAssertFalse(receivedContainer.hasValidSignature(from: carolPublicKeys))
        // Confirm that it was signed by Alice OR Carol.
        try XCTAssertTrue(receivedContainer.hasValidSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 1))
        // Confirm that it was not signed by Alice AND Carol.
        try XCTAssertFalse(receivedContainer.hasValidSignatures(from: [alicePublicKeys, carolPublicKeys], threshold: 2))

        // Bob reads the message.
        try XCTAssertEqual(receivedContainer.extract(String.self), plaintext)
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

        // ➡️ ☁️ ➡️

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

        XCTAssertEqual(container.format, "<encrypted>")

        // ➡️ ☁️ ➡️

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
        
        XCTAssertEqual(container.format, "<encrypted>")

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // ➡️ ☁️ ➡️

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
        <encrypted> [
           authenticatedBy: Signature
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // ➡️ ☁️ ➡️

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
        <encrypted> [
           hasRecipient: SealedMessage
           hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // ➡️ ☁️ ➡️

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
        <encrypted> [
           authenticatedBy: Signature
           hasRecipient: SealedMessage
           hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // ➡️ ☁️ ➡️

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
        <encrypted> [
           hasRecipient: SealedMessage
           hasRecipient: SealedMessage
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        // ➡️ ☁️ ➡️

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
        <encrypted> [
           sskrShare: SSKRShare
        ]
        """
        XCTAssertEqual(sentContainers[0].format, expectedFormat)
        
        // Dan sends one container to each of Alice, Bob, and Carol.

//        print(sentContainers[0].taggedCBOR.diag)
//        print(sentContainers[0].taggedCBOR.dump)
//        print(sentContainers[0].ur)

        // ➡️ ☁️ ➡️

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
    
    func testIDAndDigest() throws {
        let id = SCID(‡"3e507f4b9a1438aa2ff5ef41aa15cae1c98f793b6937e524c8bafd1054b1a4c1")!
        let container = try Simplex("Hello, world!")
            .setID(id)
        let expectedFormat =
        """
        "Hello, world!" [
           id: SCID(3e507f4b9a1438aa2ff5ef41aa15cae1c98f793b6937e524c8bafd1054b1a4c1)
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)
        XCTAssertEqual(container.digest.rawValue, ‡"54adf5794f448e9a0781006b1413838b65384b84beac8cd5cebda8389e2b80ea")
    }
    
//    func testReference() throws {
//        let id = SCID(‡"3e507f4b9a1438aa2ff5ef41aa15cae1c98f793b6937e524c8bafd1054b1a4c1")!
//        let container = try Simplex("Hello, world!")
//            .setID(id)
//        print(container.digestReference.taggedCBOR.diag)
//        print(container.digestReference.format)
//    }
    
    func testAssertionsOnAllPartsOfContainer() throws {
        let predicate = Simplex("predicate")
            .addAssertion(predicate: "predicate-predicate", object: "predicate-object")
        let object = Simplex("object")
            .addAssertion(predicate: "object-predicate", object: "object-object")
        let container = Simplex("subject")
            .addAssertion(predicate: predicate, object: object)
        
        let expectedFormat =
        """
        "subject" [
           {
              "predicate" [
                 "predicate-predicate": "predicate-object"
              ]
           }
           : {
              "object" [
                 "object-predicate": "object-object"
              ]
           }
        ]
        """
        XCTAssertEqual(container.format, expectedFormat)
    }
    
    func testComplexMetadata() throws {
        let author = Simplex(SCID(‡"9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8")!)
            .addAssertion(predicate: "dereferenceVia", object: "LibraryOfCongress")
            .addAssertion(predicate: "name", object: "Ayn Rand")
        
        let title_en = Simplex("Atlas Shrugged")
            .addAssertion(predicate: "language", object: "en")

        let title_es = Simplex("La rebelión de Atlas")
            .addAssertion(predicate: "language", object: "es")
        
        let work = Simplex(SCID(‡"7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80")!)
            .addAssertion(predicate: "isA", object: "novel")
            .addAssertion(predicate: "isbn", object: "9780451191144")
            .addAssertion(predicate: "author", object: author)
            .addAssertion(predicate: "dereferenceVia", object: "LibraryOfCongress")
            .addAssertion(predicate: "title", object: title_en)
            .addAssertion(predicate: "title", object: title_es)

        let bookData = "This is the entire book “Atlas Shrugged” in EPUB format."
        let bookMetadata = Simplex(Digest(bookData))
            .addAssertion(predicate: "work", object: work)
            .addAssertion(predicate: "format", object: "EPUB")
            .addAssertion(predicate: "dereferenceVia", object: "IPFS")
        
        let expectedFormat =
        """
        Digest(886d35d99ded5e20c61868e57af2f112700b73f1778d48284b0e078503d00ac1) [
           "dereferenceVia": "IPFS"
           "format": "EPUB"
           "work": {
              SCID(7fb90a9d96c07f39f75ea6acf392d79f241fac4ec0be2120f7c82489711e3e80) [
                 "author": {
                    SCID(9c747ace78a4c826392510dd6285551e7df4e5164729a1b36198e56e017666c8) [
                       "dereferenceVia": "LibraryOfCongress"
                       "name": "Ayn Rand"
                    ]
                 }
                 "dereferenceVia": "LibraryOfCongress"
                 "isA": "novel"
                 "isbn": "9780451191144"
                 "title": {
                    "Atlas Shrugged" [
                       "language": "en"
                    ]
                 }
                 "title": {
                    "La rebelión de Atlas" [
                       "language": "es"
                    ]
                 }
              ]
           }
        ]
        """
        XCTAssertEqual(bookMetadata.format, expectedFormat)
    }
}

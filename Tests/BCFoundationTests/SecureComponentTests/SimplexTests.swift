import XCTest
import BCFoundation
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
        let container = Simplex(enclose: plaintext)
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
        let container = Simplex(enclose: plaintext)
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
        let container = Simplex(enclose: plaintext)
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
        let container = try Simplex(enclose: plaintext)
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
        let plaintextContainer = Simplex(enclose: plaintext)
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
        let container = try Simplex(enclose: plaintext)
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
        let container = try Simplex(enclose: plaintext)
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
        let container = try Simplex(enclose: plaintext)
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
}

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
        let container = Simplex(plaintext: plaintext)
        let ur = container.ur
        
//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(ur)

        XCTAssertEqual(container.format, #""Hello.""#)

        // ➡️ ☁️ ➡️

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)
        // Bob reads the message.
        try XCTAssertEqual(receivedContainer.plaintext(String.self), plaintext)
    }

    func testSignedPlaintext() throws {
        // Alice sends a signed plaintext message to Bob.
        let container = Simplex(plaintext: plaintext, schnorrSigner: alicePrivateKeys)
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
        try XCTAssertEqual(receivedContainer.plaintext(String.self), plaintext)
    }
    
    func testMultisignedPlaintext() throws {
        // Alice and Carol jointly send a signed plaintext message to Bob.
        let container = Simplex(plaintext: plaintext, schnorrSigners: [alicePrivateKeys, carolPrivateKeys])
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

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)

        // Bob verifies the message was signed by both Alice and Carol.
        try XCTAssertTrue(receivedContainer.hasValidSignatures(from: [alicePublicKeys, carolPublicKeys]))

        // Bob reads the message.
        try XCTAssertEqual(receivedContainer.plaintext(String.self), plaintext)
    }
    
    func testSymmetricEncryption() throws {
        // Alice and Bob have agreed to use this key.
        let key = SymmetricKey()

        // Alice sends a message encrypted with the key to Bob.
        let container = Simplex(plaintext: plaintext, key: key)
        let ur = container.ur

//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(container.ur)

        XCTAssertEqual(container.format, #"<encrypted>"#)

        // ➡️ ☁️ ➡️

        // Bob receives the container.
        let receivedContainer = try Simplex(ur: ur)

        // Bob decrypts and reads the message.
        try XCTAssertEqual(receivedContainer.plaintext(String.self, with: key), plaintext)

        // Can't read with no key.
        try XCTAssertThrowsError(receivedContainer.plaintext(String.self))
        
        // Can't read with incorrect key.
        try XCTAssertThrowsError(receivedContainer.plaintext(String.self, with: SymmetricKey()))
    }
    
    func testEncryptDecrypt() throws {
        let key = SymmetricKey()
        let plaintextContainer = Simplex(plaintext: plaintext)
        print(plaintextContainer.format)
        let encryptedContainer = try plaintextContainer.encrypted(with: key)
        print(encryptedContainer.format)
        XCTAssertEqual(plaintextContainer, encryptedContainer)
        let plaintextContainer2 = try encryptedContainer.decrypted(with: key)
        print(plaintextContainer2.format)
        XCTAssertEqual(encryptedContainer, plaintextContainer2)
    }
}

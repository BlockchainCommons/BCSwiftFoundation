import XCTest
import BCFoundation
import WolfBase

fileprivate let plaintext = "Hello."

fileprivate let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
fileprivate let alicePrivateKeyBase = PrivateKeyBase(aliceSeed, salt: "Salt")
fileprivate let alicePeer = alicePrivateKeyBase.pubkeys

fileprivate let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
fileprivate let bobPrivateKeyBase = PrivateKeyBase(bobSeed, salt: "Salt")
fileprivate let bobPeer = bobPrivateKeyBase.pubkeys

fileprivate let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
fileprivate let carolPrivateKeyBase = PrivateKeyBase(carolSeed, salt: "Salt")
fileprivate let carolPeer = carolPrivateKeyBase.pubkeys

class SimplexTests: XCTestCase {
    func testPlaintext() throws {
        // Alice sends a plaintext message to Bob.
        let container = Simplex(plaintext: plaintext)
        let ur = container.ur
        
//        print(container.taggedCBOR.diag)
//        print(container.taggedCBOR.dump)
//        print(ur)

        // ➡️ ☁️ ➡️

        // Bob receives the envelope.
        let receivedContainer = try Simplex(ur: ur)
        // Bob reads the message.
        XCTAssertEqual(try receivedContainer.plaintext(String.self), plaintext)
    }

//    func testSignedPlaintext() throws {
//        // Alice sends a signed plaintext message to Bob.
//        let container = Simplex(plaintext: plaintext, schnorrSigner: alicePrivateKeyBase)
//        let ur = container.ur
//
////        print(envelope.taggedCBOR.diag)
////        print(envelope.taggedCBOR.dump)
////        print(envelope.ur)
//
//        // ➡️ ☁️ ➡️
//
//        // Bob receives the envelope.
//        let receivedContainer = try Simplex(ur: ur)
//        // Bob receives the message and verifies that it was signed by Alice.
//        XCTAssertTrue(receivedContainer.hasValidSignature(from: alicePeer))
//        // Confirm that it wasn't signed by Carol.
//        XCTAssertFalse(receivedContainer.hasValidSignature(from: carolPeer))
//        // Confirm that it was signed by Alice OR Carol.
//        XCTAssertTrue(receivedContainer.hasValidSignatures(from: [alicePeer, carolPeer], threshold: 1))
//        // Confirm that it was not signed by Alice AND Carol.
//        XCTAssertFalse(receivedContainer.hasValidSignatures(from: [alicePeer, carolPeer], threshold: 2))
//
//        // Bob reads the message.
//        XCTAssertEqual(receivedContainer.plaintext, plaintext)
//    }
}

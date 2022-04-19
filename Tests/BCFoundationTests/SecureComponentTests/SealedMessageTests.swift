import XCTest
@testable import BCFoundation
import WolfBase
import CryptoKit

fileprivate let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

fileprivate let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
fileprivate let alicePrivateKeys = PrivateKeyBase(aliceSeed, salt: "Salt")
fileprivate let alicePublicKeys = alicePrivateKeys.publicKeys

fileprivate let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
fileprivate let bobPrivateKeys = PrivateKeyBase(bobSeed, salt: "Salt")
fileprivate let bobPublicKeys = bobPrivateKeys.publicKeys

fileprivate let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
fileprivate let carolPrivateKeys = PrivateKeyBase(carolSeed, salt: "Salt")
fileprivate let carolPublicKeys = carolPrivateKeys.publicKeys

class SealedMessageTests: XCTestCase {
    func testSealedMessage() {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintext, recipient: bobPublicKeys)
        
        // Bob decrypts and reads the message.
        XCTAssertEqual(sealedMessage.plaintext(with: bobPrivateKeys), plaintext)
        
        // No one else can decrypt the message, not even the sender.
        XCTAssertNil(sealedMessage.plaintext(with: alicePrivateKeys))
        XCTAssertNil(sealedMessage.plaintext(with: carolPrivateKeys))
    }
}

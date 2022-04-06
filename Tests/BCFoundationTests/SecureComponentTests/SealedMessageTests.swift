import XCTest
@testable import BCFoundation
import WolfBase
import CryptoKit

fileprivate let plaintext = "Some mysteries aren't meant to be solved.".utf8Data

fileprivate let aliceSeed = Seed(data: ‡"82f32c855d3d542256180810797e0073")!
fileprivate let aliceProfile = Profile(aliceSeed, salt: "Salt")
fileprivate let alicePeer = aliceProfile.peer

fileprivate let bobSeed = Seed(data: ‡"187a5973c64d359c836eba466a44db7b")!
fileprivate let bobProfile = Profile(bobSeed, salt: "Salt")
fileprivate let bobPeer = bobProfile.peer

fileprivate let carolSeed = Seed(data: ‡"8574afab18e229651c1be8f76ffee523")!
fileprivate let carolProfile = Profile(carolSeed, salt: "Salt")
fileprivate let carolPeer = carolProfile.peer

class SealedMessageTests: XCTestCase {
    func testSealedMessage() {
        // Alice constructs a message for Bob's eyes only.
        let sealedMessage = SealedMessage(plaintext: plaintext, receiver: bobPeer)
        
        // Bob decrypts and reads the message.
        XCTAssertEqual(sealedMessage.plaintext(with: bobProfile), plaintext)
        
        // No one else can decrypt the message, not even the sender.
        XCTAssertNil(sealedMessage.plaintext(with: aliceProfile))
        XCTAssertNil(sealedMessage.plaintext(with: carolProfile))
    }
}

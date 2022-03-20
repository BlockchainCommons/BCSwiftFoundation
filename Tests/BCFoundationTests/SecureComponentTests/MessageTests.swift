import XCTest
import BCFoundation
import WolfBase

class MessageTests: XCTestCase {
    // Test vector from: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    static let plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
    static let aad = Data(hex: "50515253c0c1c2c3c4c5c6c7")!
    static let key = Message.Key(rawValue: Data(hex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")!)!
    static let nonce = Message.Nonce(rawValue: Data(hex: "070000004041424344454647")!)!
    static let secureMessage = Message(plaintext: plaintext, key: key, aad: aad, nonce: nonce)
    static let ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116".hexData!
    static let auth = Message.Auth(rawValue: Data(hex: "1ae10b594f09e26a7e902ecbd0600691")!)!

    func testRFCTestVector() throws {
        XCTAssertEqual(Self.secureMessage.ciphertext, Self.ciphertext)
        XCTAssertEqual(Self.secureMessage.auth, Self.auth)

        let decryptedPlaintext = Self.key.decrypt(message: Self.secureMessage)
        XCTAssertEqual(Self.plaintext, decryptedPlaintext)
    }
    
    func testRandomKeyAndNonce() {
        let key = Message.Key()
        let nonce = Message.Nonce()
        let secureMessage = Message(plaintext: Self.plaintext, key: key, aad: Self.aad, nonce: nonce)
        let decryptedPlaintext = key.decrypt(message: secureMessage)
        XCTAssertEqual(Self.plaintext, decryptedPlaintext)
    }
    
    func testEmptyData() {
        let key = Message.Key()
        let nonce = Message.Nonce()
        let secureMessage = Message(plaintext: Data(), key: key, aad: Data(), nonce: nonce)
        let decryptedPlaintext = key.decrypt(message: secureMessage)
        XCTAssertEqual(Data(), decryptedPlaintext)
    }
    
    func testCBOR() {
        let expectedCBOR = "d83085015872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61164c50515253c0c1c2c3c4c5c6c74c070000004041424344454647501ae10b594f09e26a7e902ecbd0600691".hexData!
        XCTAssertEqual(Self.secureMessage.taggedCBOR.encoded, expectedCBOR)
    }
    
    func testUR() {
        let expectedUR = try! UR(urString: "ur:crypto-msg/lpadhdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzeptvoreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbonrpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufdehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmgsgdgygmgurtsesasrssskswstgsataeaeaefzfpfwfxfyfefgflgdcyvybdhkgwasvoimkbmhdmsbtihnammeihgudrjp")
        XCTAssertEqual(Self.secureMessage.ur, expectedUR)
    }
}

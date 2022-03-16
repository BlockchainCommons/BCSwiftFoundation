import XCTest
import BCFoundation
import WolfBase

class SecureMessageTests: XCTestCase {
    // Test vector from: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    static let plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
    static let aad = Data(hex: "50515253c0c1c2c3c4c5c6c7")!
    static let key = SecureMessage.Key(Data(hex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")!)!
    static let nonce = SecureMessage.Nonce(Data(hex: "070000004041424344454647")!)!
    static let secureMessage = SecureMessage(plaintext: plaintext, aad: aad, key: key, nonce: nonce)!
    static let ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116".hexData!
    static let auth = SecureMessage.Auth(Data(hex: "1ae10b594f09e26a7e902ecbd0600691")!)!

    func testRFCTestVector() throws {
        XCTAssertEqual(Self.secureMessage.ciphertext, Self.ciphertext)
        XCTAssertEqual(Self.secureMessage.auth, Self.auth)

        let decryptedSecureMessage = SecureMessage(ciphertext: Self.ciphertext, aad: Self.aad, key: Self.key, nonce: Self.nonce, auth: Self.secureMessage.auth)!
        XCTAssertEqual(Self.secureMessage, decryptedSecureMessage)
    }
    
    func testRandomKeyAndNonce() {
        let key = SecureMessage.Key()
        let nonce = SecureMessage.Nonce()
        let secureMessage = SecureMessage(plaintext: Self.plaintext, aad: Self.aad, key: key, nonce: nonce)!
        let decryptedSecureMessage = SecureMessage(ciphertext: secureMessage.ciphertext, aad: Self.aad, key: key, nonce: nonce, auth: secureMessage.auth)!
        XCTAssertEqual(secureMessage, decryptedSecureMessage)
    }
    
    func testEmptyData() {
        let key = SecureMessage.Key()
        let nonce = SecureMessage.Nonce()
        let secureMessage = SecureMessage(plaintext: Data(), aad: Data(), key: key, nonce: nonce)!
        let decryptedSecureMessage = SecureMessage(ciphertext: secureMessage.ciphertext, aad: Data(), key: key, nonce: nonce, auth: secureMessage.auth)!
        XCTAssertEqual(secureMessage, decryptedSecureMessage)
    }
    
    func testCBOR() {
        let expectedCBOR = "d83085014c070000004041424344454647501ae10b594f09e26a7e902ecbd06006914c50515253c0c1c2c3c4c5c6c75872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116".hexData!
        XCTAssertEqual(Self.secureMessage.taggedCBOR.encoded, expectedCBOR)
    }
    
    func testUR() {
        let expectedUR = try! UR(urString: "ur:crypto-msg/lpadgsataeaeaefzfpfwfxfyfefgflgdcyvybdhkgwasvoimkbmhdmsbtihnammegsgdgygmgurtsesasrssskswsthdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzeptvoreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbonrpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufdehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmpmdpasgm")
        XCTAssertEqual(Self.secureMessage.ur, expectedUR)
    }
}

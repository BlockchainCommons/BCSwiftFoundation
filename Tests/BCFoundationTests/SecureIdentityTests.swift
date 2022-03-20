import XCTest
import BCFoundation
import WolfBase

class SecureIdentityTests: XCTestCase {
    func test1() {
        let seed = Seed(data: "59f2293a5bce7d4de59e71b4207ac5d2".hexData!)!
        let identity = SecureIdentity(seed, salt: "salt")
        
        XCTAssertEqual(identity.signingPrivateKey.rawValue, "d1a0b434271f358cabb9f077f659c526ab0c05574b9f915a63cee828bfc1ed42".hexData!)
        XCTAssertEqual(identity.signingPublicKey.rawValue, "8005235501da7de04f16acdd8aa1ba9b2515346c2c532f430f49a8fbf3c8a2c8".hexData!)
        XCTAssertEqual(identity.agreementPrivateKey.rawValue, "62a5dc3041aba9ae2101158ff4af895692d540f69b2e3cf86f894952c0c9c076".hexData!)
        XCTAssertEqual(identity.agreementPublicKey.rawValue, "aa4e5fc2b0e8f4a43dbae483c146e15b748675ce39d051fd21f7fe415f996a2c".hexData!)
    }
}

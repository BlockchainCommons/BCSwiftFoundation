import XCTest
import BCFoundation
import WolfBase

class PrivateKeyBaseTests: XCTestCase {
    func testPrivateKeyBase() {
        let seed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        let privateKeys = PrivateKeyBase(seed)
        
//         print(privateKeys.signingPrivateKey.data.hex)
//         print(privateKeys.signingPrivateKey.schnorrPublicKey.data.hex)
//         print(privateKeys.agreementPrivateKey.data.hex)
//         print(privateKeys.agreementPrivateKey.publicKey.data.hex)
        
        XCTAssertEqual(privateKeys.signingPrivateKey.data, ‡"d7506e77dca4e51187f973a9ae0d607650fbc38e90c8b83b2e9c4219a320b4d1")
        XCTAssertEqual(privateKeys.signingPrivateKey.schnorrPublicKey.data, ‡"d741926a8b46880d56f1b1bb9a3f280732a0c5b480b988f57782c1ca9d51b70a")
        XCTAssertEqual(privateKeys.agreementPrivateKey.data, ‡"454cb16fa7508d93c6fdc7eff6359ad91a71ffb763bbe8d99c4e43b7f82806bf")
        XCTAssertEqual(privateKeys.agreementPrivateKey.publicKey.data, ‡"c16cabdc86ae548d4ca6683c6ae988356a1e15672090a4eab75a74b95fd6a71b")
    }
}

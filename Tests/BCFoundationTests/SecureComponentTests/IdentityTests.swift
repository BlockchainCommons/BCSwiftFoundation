import XCTest
import BCFoundation
import WolfBase

class IdentityTests: XCTestCase {
    func testIdentity() {
        let seed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        let identity = Identity(seed, salt: "salt")
        
        // print(identity.signingPrivateKey.rawValue.hex)
        // print(identity.signingPublicKey.rawValue.hex)
        // print(identity.agreementPrivateKey.rawValue.hex)
        // print(identity.agreementPublicKey.rawValue.hex)
        
        XCTAssertEqual(identity.signingPrivateKey.data, ‡"79dfae4060d2c79c9588b0108307c3edc486840ca5e809badd9aa7296913b2a6")
        XCTAssertEqual(identity.signingPrivateKey.schnorrPublicKey.data, ‡"72dd19bc0ebf5ba3dc2abc68b121e89f35169fb481ef3efed6beea30fc4b7759")
        XCTAssertEqual(identity.agreementPrivateKey.data, ‡"5566b162781c0294a051209131e0c606c37f2c359515aa0160ad3a3255b9deb4")
        XCTAssertEqual(identity.agreementPrivateKey.publicKey.data, ‡"040b0105518b038012319b5956059a7601bd8ada36b4e98386e801789627a40d")
    }
}

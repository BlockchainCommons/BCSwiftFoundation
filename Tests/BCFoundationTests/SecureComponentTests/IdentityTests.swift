import XCTest
import BCFoundation
import WolfBase

class IdentityTests: XCTestCase {
    func testIdentity() {
        let seed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        let identity = Identity(seed, salt: "salt")
        
        // print(identity.privateSigningKey.rawValue.hex)
        // print(identity.publicSigningKey.rawValue.hex)
        // print(identity.privateAgreementKey.rawValue.hex)
        // print(identity.publicAgreementKey.rawValue.hex)
        
        XCTAssertEqual(identity.privateSigningKey.rawValue, ‡"79dfae4060d2c79c9588b0108307c3edc486840ca5e809badd9aa7296913b2a6")
        XCTAssertEqual(identity.publicSigningKey.rawValue, ‡"ad23ba21cfa868c707a1609426af90931ce59975bab9171e0458dcf29cdc1ce5")
        XCTAssertEqual(identity.privateAgreementKey.rawValue, ‡"5566b162781c0294a051209131e0c606c37f2c359515aa0160ad3a3255b9deb4")
        XCTAssertEqual(identity.publicAgreementKey.rawValue, ‡"040b0105518b038012319b5956059a7601bd8ada36b4e98386e801789627a40d")
    }
}

import XCTest
import BCFoundation
import WolfBase

class ProfileTests: XCTestCase {
    func testProfile() {
        let seed = Seed(data: ‡"59f2293a5bce7d4de59e71b4207ac5d2")!
        let profile = Profile(seed, salt: "salt")
        
        // print(profile.signingPrivateKey.rawValue.hex)
        // print(profile.signingPublicKey.rawValue.hex)
        // print(profile.agreementPrivateKey.rawValue.hex)
        // print(profile.agreementPublicKey.rawValue.hex)
        
        XCTAssertEqual(profile.signingPrivateKey.data, ‡"79dfae4060d2c79c9588b0108307c3edc486840ca5e809badd9aa7296913b2a6")
        XCTAssertEqual(profile.signingPrivateKey.schnorrPublicKey.data, ‡"72dd19bc0ebf5ba3dc2abc68b121e89f35169fb481ef3efed6beea30fc4b7759")
        XCTAssertEqual(profile.agreementPrivateKey.data, ‡"5566b162781c0294a051209131e0c606c37f2c359515aa0160ad3a3255b9deb4")
        XCTAssertEqual(profile.agreementPrivateKey.publicKey.data, ‡"040b0105518b038012319b5956059a7601bd8ada36b4e98386e801789627a40d")
    }
}

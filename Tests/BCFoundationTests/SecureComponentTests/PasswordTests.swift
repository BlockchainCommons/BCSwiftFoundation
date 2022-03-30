import XCTest
import BCFoundation
import WolfBase

class PasswordTests: XCTestCase {
    // Disabled because Scrypt is slow.
    func _testPassword() {
        let password = "fnord"
        let securePassword = Password(password, salt: "salt")!
        XCTAssertEqual(securePassword.identityData, ‡"0174464c3810fbd157f9f33416e43fd6fa96cb1aba8a897747b4e339f68f8a5a")
        XCTAssertTrue(securePassword.validate(password))
        XCTAssertFalse(securePassword.validate("blat"))
    }
}

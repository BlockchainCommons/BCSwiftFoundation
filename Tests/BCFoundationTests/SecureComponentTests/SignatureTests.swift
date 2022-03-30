import XCTest
import WolfBase
import BCFoundation

class SignatureTests: XCTestCase {
    static let privateKey = SchnorrPrivateKey(rawValue: ‡"322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")!
    static let publicKey = privateKey.publicKey
    static let message = "Wolf McNally"
    static let signature = privateKey.sign(message)

    func testSigning() {
        print(Self.signature.data.hex)
        XCTAssertTrue(Self.publicKey.isValidSignature(Self.signature, for: Self.message))
        XCTAssertFalse(Self.publicKey.isValidSignature(Self.signature, for: "Wolf Mcnally"))
        
        let anotherSignature = Self.privateKey.sign(Self.message)
        XCTAssertNotEqual(Self.signature, anotherSignature)
        XCTAssertTrue(Self.publicKey.isValidSignature(anotherSignature, for: Self.message))
    }
    
    func testCBOR() throws {
        let taggedCBOR = Self.signature.taggedCBOR.encoded
        let receivedSignature = try Signature(taggedCBOR: taggedCBOR)
        XCTAssertEqual(Self.signature, receivedSignature)
    }
}

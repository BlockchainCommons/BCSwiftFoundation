import XCTest
import WolfBase
import BCFoundation

fileprivate let privateKey = SigningPrivateKey(‡"322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")!
fileprivate let message = "Wolf McNally"

class SchnorrSignatureTests: XCTestCase {
    let publicKey = privateKey.schnorrPublicKey
    let signature = privateKey.schnorrSign(message)

    func testSigning() {
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: "Wolf Mcnally"))
        
        let anotherSignature = privateKey.schnorrSign(message)
        XCTAssertNotEqual(signature, anotherSignature)
        XCTAssertTrue(publicKey.isValidSignature(anotherSignature, for: message))
    }
    
    func testCBOR() throws {
        let taggedCBOR = signature.taggedCBOR.cborEncode
        let receivedSignature = try Signature(taggedCBOR: taggedCBOR)
        XCTAssertEqual(signature, receivedSignature)
    }
}

class ECDSASignatureTests: XCTestCase {
    let publicKey = privateKey.ecdsaPublicKey
    let signature = privateKey.ecdsaSign(message)

    func testSigning() {
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: "Wolf Mcnally"))
        
        let anotherSignature = privateKey.ecdsaSign(message)
        XCTAssertEqual(signature, anotherSignature)
        XCTAssertTrue(publicKey.isValidSignature(anotherSignature, for: message))
    }
    
    func testCBOR() throws {
        let taggedCBOR = signature.taggedCBOR.cborEncode
        let receivedSignature = try Signature(taggedCBOR: taggedCBOR)
        XCTAssertEqual(signature, receivedSignature)
    }
}

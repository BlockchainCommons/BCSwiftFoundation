import XCTest
import WolfBase
import BCFoundation

class SignatureTests: XCTestCase {
    static let privateKey = PrivateSigningKey(rawValue: ‡"322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36")!
    static let publicKey = PublicSigningKey(privateKey)
    static let message = "Wolf McNally".utf8Data
    static let digest = Digest(data: message)
    static let signature = privateKey.sign(data: digest)

    func testSigning() {
        XCTAssertTrue(Self.publicKey.isValidSignature(Self.signature, for: Self.digest))
    }
    
    /// Test vector from: https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
    func testRFC() {
        let privateKey = PrivateSigningKey(rawValue: ‡"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")!
        let publicKey = PublicSigningKey(privateKey)
        let expectedPublicKey = PublicSigningKey(rawValue: ‡"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")!
        XCTAssertEqual(publicKey, expectedPublicKey)
        let message = ‡"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        let sig = Signature(rawValue: ‡"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")!
        XCTAssertTrue(publicKey.isValidSignature(sig, for: message))
    }
    
    func testCBOR() throws {
        let taggedCBOR = Self.signature.taggedCBOR.encoded
        let receivedSignature = try Signature(taggedCBOR: taggedCBOR)
        XCTAssertEqual(Self.signature, receivedSignature)
    }
    
    func testUR() throws {
        let ur = Self.signature.ur
        let receivedSignature = try Signature(ur: ur)
        XCTAssertEqual(Self.signature, receivedSignature)
    }
}

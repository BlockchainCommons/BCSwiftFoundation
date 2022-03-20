import XCTest
import WolfBase
@testable import BCFoundation

class DigestTests: XCTestCase {
    static let secureDigest = Digest(data: "Wolf McNally".utf8Data)
    
    func testVectors() {
        // Test vectors from https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
        let data = [
            "",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
        ].map { $0.hexData! }
        let expectedDigest = [
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b",
            "bfbabbef45554ccfa0dc83752a19cc35d5920956b301d558d772282bc867009168e9e98606bb5ba73a385de5749228c925a85019b71f72fe29b3cd37ca52efe6",
            "f15ab26d4cdfcf56e196bb6ba170a8fccc414de9285afd98a3d3cf2fb88fcbc0f19832ac433a5b2cc2392a4ce34332987d8d2c2bef6c3466138db0c6e42fa47b"
        ].map { Digest(rawValue: $0.hexData!, digestLength: 64)! }
        let digest = data.map { Digest(data: $0, digestLength: 64) }
        XCTAssertEqual(digest, expectedDigest)
    }
    
    func testSimple() {
        XCTAssertEqual(
            Self.secureDigest,
            Digest(rawValue: "4d0c1a8e4d2bbdf766c8ec46c9f62541fbe6285cacc8fda743eed9120b6a958b".hexData!)
        )
    }
    
    func testCBOR() {
        XCTAssertEqual(
            Self.secureDigest.taggedCBOR.encoded,
            "d831820158204d0c1a8e4d2bbdf766c8ec46c9f62541fbe6285cacc8fda743eed9120b6a958b".hexData!
        )
    }
    
    func testUR() {
        let expectedUR = try! UR(urString: "ur:crypto-digest/lfadhdcxgtbncymngtdnryyliyspwpfgsoyndafpzovadehhpsspzcosfxwytabgbdimmdlugebsiepy")
        XCTAssertEqual(Self.secureDigest.ur, expectedUR)
    }
}

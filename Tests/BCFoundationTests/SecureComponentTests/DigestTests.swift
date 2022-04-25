import XCTest
import WolfBase
@testable import BCFoundation

fileprivate let secureDigest = Digest("Wolf McNally")

class DigestTests: XCTestCase {
    func inputSequence(_ count: Int) -> Data {
        Data(sequence(first: 0, next: { UInt8(($0 + 1) % 251) }).prefix(count))
    }
    
    func testVectors() {
        // Test vectors from https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
        let inputSizes = [0, 1, 65, 31744]
        let expectedDigests = [
            ‡"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
            ‡"2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
            ‡"de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee0e16e0a4749d6811dd1d6d1265c29729b1b75a9ac346cf93f0e1d7296dfcfd4313b3a227faaaaf7757cc95b4e87a49be3b8a270a12020233509b1c3632b3485eef309d0abc4a4a696c9decc6e90454b53b000f456a3f10079072baaf7a981653221f2c",
            ‡"62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f"
        ]
        zip(inputSizes, expectedDigests).forEach { inputSize, expectedDigestData in
            let expectedDigest = Digest(rawValue: expectedDigestData, digestLength: expectedDigestData.count)!
            let digest = Digest(inputSequence(inputSize), digestLength: expectedDigestData.count)
            XCTAssertEqual(digest, expectedDigest)
        }
    }
    
    func testSimple() {
        XCTAssertEqual(
            secureDigest,
            Digest(rawValue: ‡"50f97c3d91dde7faf12a10272c1627be2902581b27051a485f8e7162c4c914d2")
        )
    }
    
    func testCBOR() {
        let expected =
        """
        56(
           h'50f97c3d91dde7faf12a10272c1627be2902581b27051a485f8e7162c4c914d2'
        )
        """
        XCTAssertEqual(secureDigest.taggedCBOR.diag, expected)
    }
}

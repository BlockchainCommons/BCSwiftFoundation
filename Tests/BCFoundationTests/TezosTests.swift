import XCTest
import BCFoundation
import WolfBase

class TezosTests: XCTestCase {
    func testFormats() {
        let privateKey = ECPrivateKey(‡"bb94bb005d190f67d84ed58c153b7ed5c6e40fc2ca7f4140d0e2c32ddd50dd57")!
        
        XCTAssertEqual(privateKey.tezosFormat, "spsk2rBBj5a6ahir2xZwbNkdeBuyZTxQZC9Pr6UvSAM4GNPeXfM3ix")
        
        let publicKey = privateKey.publicKey
        XCTAssertEqual(publicKey.tezosFormat, "sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP")
        
        XCTAssertEqual(publicKey.tezosAddress, "tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s")
    }
}

import Testing
import BCFoundation
import WolfBase

struct TezosTests {
    // Ed25519
    @Test func testFormats1() {
        let privateKey = ECPrivateKey(‡"ed6f322e5b6b3744e10c2dce1659c0f59ad5aa9db0494e223bb729d03608773c")!
        
        #expect(privateKey.tezos1Format == "edskS95SXn6MnWAtAL3mSrX6TmdWRjg5uwYTT99VVsR3b3DNX8CE2SHdsGCshR4ncYyJxWCyEzFDNjXNyTtXzq3SqWcxmsFNYZ")
        
        let publicKey = privateKey.ed25519PublicKey
        #expect(publicKey.tezos1Format == "edpkvVo4fLdJ5wrNC4eKLYafG78rhwwkkDAHew4y6CAPA9mno3XF93")
        
        #expect(publicKey.tezos1Address == "tz1V1iyRr7gzs9uhup4cdGiWyDXc5K2yYXo9")
    }

    // Secp256k1
    @Test func testFormats2() {
        let privateKey = ECPrivateKey(‡"bb94bb005d190f67d84ed58c153b7ed5c6e40fc2ca7f4140d0e2c32ddd50dd57")!
        
        #expect(privateKey.tezos2Format == "spsk2rBBj5a6ahir2xZwbNkdeBuyZTxQZC9Pr6UvSAM4GNPeXfM3ix")
        
        let publicKey = privateKey.secp256k1PublicKey
        #expect(publicKey.tezos2Format == "sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP")
        
        #expect(publicKey.tezos2Address == "tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s")
    }
}

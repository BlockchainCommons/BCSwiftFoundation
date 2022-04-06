import XCTest
import WolfBase
import BCFoundation

class CryptoToolTests: XCTestCase {
    func test1() throws {
        let message = "Hello, world!"
//        let digest = Digest(message)
//        print(digest.rawValue.hex)
//        print(digest.ur)
//        print(digest.taggedCBOR.hex)
//
//        let envelope = Envelope(plaintext: message)
//        print(envelope.taggedCBOR.hex)
//        print(envelope.ur)
        
//        let digest = Digest(envelope.taggedCBOR)
//        print(digest.rawValue.hex)
//        print(digest.taggedCBOR.hex)
        
//        print(message.utf8Data.hex)
        
//        let key = SymmetricKey(‡"6eaaad983b275c3afacbd661f0aaf33789b42bbabeb51696d08d4bbaef129d54")!
//        print(key.data.hex)
//        print(key.ur)
//        let envelope = Envelope(plaintext: message, key: key)
//        print(envelope.ur)
        
//        let profile = Profile()
//        print(profile.ur)
        
        let ur = try UR(urString: "ur:crypto-profile/lsadhdcxsofssasgpmrfdyrtiavoinbepabseyfnttcnfmdyzcktwnmsbzgsqzfhksiezclagdioeshtqzzmkplamkehpklylejztszowywmztjpme")
        let profile = try Profile(ur: ur)
        let peer = profile.peer
        print(peer.ur)
    }
}

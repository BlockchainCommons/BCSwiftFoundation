import Foundation
import WolfBase
import BCCrypto

public extension ECPrivateKey {
    var tezosFormat: String {
        let d = ‡"11a2e0c9" + data // `spsk`
        return d.base58(isCheck: true)
    }
}

public extension ECPublicKey {
    var tezosFormat: String {
        let d = ‡"03fee256" + data // `sppk`
        return d.base58(isCheck: true)
    }
    
    var tezosAddress: String {
        let digest = blake2b(data, len: 20)
        let d = ‡"06a1a1" + digest // `tz2`
        return d.base58(isCheck: true)
    }
}

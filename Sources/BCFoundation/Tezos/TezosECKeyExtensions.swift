import Foundation
import WolfBase
import BCCrypto

// Format 1: Ed25519
// Format 2: Secp256k1

public extension ECPrivateKey {
    var tezos1Format: String {
        let d = ‡"2bf64e07" + data + ed25519PublicKey.data // `edsk`
        return d.base58(isCheck: true)
    }
    
    var tezos2Format: String {
        let d = ‡"11a2e0c9" + data // `spsk`
        return d.base58(isCheck: true)
    }
}

public extension SecP256K1PublicKey {
    var tezos2Format: String {
        let d = ‡"03fee256" + data // `sppk`
        return d.base58(isCheck: true)
    }
    
    var tezos2Address: String {
        let digest = BLAKE2b.hash(data, len: 20)
        let d = ‡"06a1a1" + digest // `tz2`
        return d.base58(isCheck: true)
    }
}
    
public extension Ed25519PublicKey {
    var tezos1Format: String {
        let d = ‡"0d0f25d9" + data // `edpk`
        return d.base58(isCheck: true)
    }

    var tezos1Address: String {
        let digest = BLAKE2b.hash(data, len: 20)
        let d = ‡"06a19f" + digest // `tz1`
        return d.base58(isCheck: true)
    }
}

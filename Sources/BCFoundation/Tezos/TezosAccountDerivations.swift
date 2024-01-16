
import Foundation

extension AccountDerivations {
    public var tezosAddress: Tezos.Address? {
        guard
            useInfo.asset == .xtz,
            let accountEd25519PublicKey = accountEd25519PublicKey
        else {
            return nil
        }
        return Tezos.Address(key: accountEd25519PublicKey, network: useInfo.network)
    }
}

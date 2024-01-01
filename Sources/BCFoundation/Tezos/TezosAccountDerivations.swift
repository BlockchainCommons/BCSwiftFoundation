
import Foundation

extension AccountDerivations {
    public var tezosAddress: Tezos.Address? {
        guard
            useInfo.asset == .xtz,
            let accountECPublicKey = accountECPublicKey
        else {
            return nil
        }
        return Tezos.Address(key: accountECPublicKey, network: useInfo.network)
    }
}

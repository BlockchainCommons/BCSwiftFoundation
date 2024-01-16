import Foundation

extension Tezos {
    public struct Address: AddressProtocol {
        public let useInfo: UseInfo
        public let string: String
        
        public init?(string: String, network: Network) {
            guard
                string.count == 36,
                string.hasPrefix("tz1")
            else {
                return nil
            }
            self.string = string.lowercased()
            self.useInfo = UseInfo(asset: .xtz, network: network)
        }
        
        public init(key: any Ed25519Key, network: Network) {
            self.string = key.ed25519PublicKey.tezos1Address
            self.useInfo = UseInfo(asset: .eth, network: network)
        }
        
        public init?(hdKey: HDKey) {
            guard let publicKey = hdKey.ecPrivateKey?.ed25519PublicKey else {
                return nil
            }
            self.init(key: publicKey, network: hdKey.useInfo.network)
        }

        public var description: String {
            string
        }
    }
}

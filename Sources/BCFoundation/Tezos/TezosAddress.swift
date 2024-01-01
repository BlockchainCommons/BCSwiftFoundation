import Foundation

extension Tezos {
    public struct Address: AddressProtocol {
        public let useInfo: UseInfo
        public let string: String
        
        public init?(string: String, network: Network) {
            guard
                string.count == 36,
                string.hasPrefix("tz2")
            else {
                return nil
            }
            self.string = string.lowercased()
            self.useInfo = UseInfo(asset: .xtz, network: network)
        }
        
        public init(key: any ECKey, network: Network) {
            self.string = key.publicKey.tezosAddress
            self.useInfo = UseInfo(asset: .eth, network: network)
        }
        
        public init(hdKey: HDKey) {
            self.init(key: hdKey.ecPublicKey, network: hdKey.useInfo.network)
        }

        public var description: String {
            string
        }
    }
}

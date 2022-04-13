import Foundation

public struct Nonce: CustomStringConvertible, Equatable, Hashable, RawRepresentable {
    public let rawValue: Data
    
    public init?(rawValue: Data) {
        guard rawValue.count == 12 else {
            return nil
        }
        self.rawValue = rawValue
    }
    
    public init() {
        self.init(rawValue: SecureRandomNumberGenerator.shared.data(count: 12))!
    }

    public var bytes: [UInt8] {
        rawValue.bytes
    }
    
    public var description: String {
        rawValue.hex.flanked("Nonce(", ")")
    }
}

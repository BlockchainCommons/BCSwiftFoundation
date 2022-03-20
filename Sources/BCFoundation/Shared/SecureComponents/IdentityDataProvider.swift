import Foundation

public protocol IdentityDataProvider {
    var identityData: Data { get }
}

extension Seed: IdentityDataProvider {
    public var identityData: Data {
        data
    }
}

extension HDKey: IdentityDataProvider {
    public var identityData: Data {
        keyData
    }
}

extension Data: IdentityDataProvider {
    public var identityData: Data {
        self
    }
}

import Foundation

public protocol SecureIdentityDataProvider {
    var identityData: Data { get }
}

extension Seed: SecureIdentityDataProvider {
    public var identityData: Data {
        data
    }
}

extension HDKey: SecureIdentityDataProvider {
    public var identityData: Data {
        keyData
    }
}

extension Data: SecureIdentityDataProvider {
    public var identityData: Data {
        self
    }
}

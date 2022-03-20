import Foundation

public protocol DataProvider {
    var providedData: Data { get }
}

extension Data: DataProvider {
    public var providedData: Data {
        self
    }
}

extension String: DataProvider {
    public var providedData: Data {
        utf8Data
    }
}

extension CBOR: DataProvider {
    public var providedData: Data {
        encoded
    }
}

extension Digest: DataProvider {
    public var providedData: Data {
        rawValue
    }
}

import Foundation
import WolfBase

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

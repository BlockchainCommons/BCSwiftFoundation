import Foundation
import WolfBase

extension CBOR: DataProvider {
    public var providedData: Data {
        cborEncode
    }
}

extension Digest: DataProvider {
    public var providedData: Data {
        rawValue
    }
}

import Foundation
import WolfBase

extension Digest: DataProvider {
    public var providedData: Data {
        data
    }
}

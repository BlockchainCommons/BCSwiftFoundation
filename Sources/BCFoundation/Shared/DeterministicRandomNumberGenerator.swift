import Foundation
import WolfBase

public final class DeterministicRandomNumberGenerator: RandomNumberGenerator {
    public let data: Data
    var position = 0
    
    public init(_ data: DataProvider) {
        self.data = data.providedData
    }
    
    public init(entropy: DataProvider, count: Int = 32) {
        self.data = deterministicRandom(entropy: entropy, count: count)
    }
    
    public func next() -> UInt64 {
        UInt64(bigEndianBytes: data(count: 8))
    }
    
    public func nextByte() -> UInt8 {
        guard !data.isEmpty else {
            return 0
        }
        defer {
            position = (position + 1) % data.count
        }
        return data[position]
    }

    public func data(count: Int) -> Data {
        Data((0..<count).map { _ in nextByte() })
    }
    
    public func reset() {
        position = 0
    }
}

import Foundation

extension Set {
    public mutating func insert<E>(_ element: E) where Element == Digest, E: DigestProvider {
        insert(element.digest)
    }
    
    public mutating func insert<S>(_ other: S) where Element == Digest, S.Element == Digest, S: Sequence {
        formUnion(other)
    }

    public mutating func insert<S>(_ other: S) where Element == Digest, S.Element == DigestProvider, S: Sequence {
        formUnion(other.map { $0.digest })
    }
}

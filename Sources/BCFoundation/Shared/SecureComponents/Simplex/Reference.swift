import Foundation
import WolfBase

public enum Reference {
    case digest(Digest)
    case id(SCID, Digest)
}

extension Reference {
    public init(digest: Digest) {
        self = .digest(digest)
    }
    
    public init(id: SCID) {
        self = .id(id, Digest(id.rawValue))
    }
    
    public var digest: Digest {
        switch self {
        case .digest(let digest):
            return digest
        case .id(_, let digest):
            return digest
        }
    }
}

extension Reference: Equatable {
    public static func ==(lhs: Reference, rhs: Reference) -> Bool {
        lhs.digest == rhs.digest
    }
}

extension Reference {
    var untaggedCBOR: CBOR {
        switch self {
        case .digest(let digest):
            return digest.taggedCBOR
        case .id(let id, _):
            return id.taggedCBOR
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        todo()
    }
}

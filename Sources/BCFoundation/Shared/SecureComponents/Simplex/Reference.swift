import Foundation
import WolfBase

public enum Reference {
    case digest(Digest)
    case scid(SCID, Digest)
}

extension Reference {
    public init(digest: Digest) {
        self = .digest(digest)
    }
    
    public init(uuid: SCID) {
        self = .scid(uuid, Digest(uuid.serialized))
    }
    
    public var digest: Digest {
        switch self {
        case .digest(let digest):
            return digest
        case .scid(_, let digest):
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
        case .scid(let scid, _):
            return scid.taggedCBOR
        }
    }
    
    init(untaggedCBOR: CBOR) throws {
        todo()
    }
}

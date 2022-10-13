import Foundation
import BCFoundation

public struct Receipt: Hashable {
    let data: Data
    
    init(_ data: Data) {
        self.data = data
    }
    
    init(userID: CID, payload: Data) {
        self.data = Digest(userID.data + payload).data
    }
}

extension Receipt: CustomStringConvertible {
    public var description: String {
        "Receipt(\(data.hex))"
    }
}

public extension Receipt {
    var untaggedCBOR: CBOR {
        CBOR.data(self.data)
    }
    
    init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.data(data) = untaggedCBOR
        else {
            throw CBORError.invalidFormat
        }
        self = Receipt(data)
    }

    var taggedCBOR: CBOR {
        CBOR.tagged(.receipt, untaggedCBOR)
    }

    init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.receipt, untaggedCBOR) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

extension Receipt: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> Receipt {
        try Receipt(taggedCBOR: cbor)
    }
    
    public var cbor: URKit.CBOR {
        taggedCBOR
    }
}

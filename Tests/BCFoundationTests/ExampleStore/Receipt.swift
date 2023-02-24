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

extension Receipt: CBORTaggedCodable {
    public static var cborTag: Tag = .receipt
    
    public var untaggedCBOR: CBOR {
        CBOR.bytes(self.data)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(data) = untaggedCBOR
        else {
            throw CBORDecodingError.invalidFormat
        }
        self = Receipt(data)
    }
}

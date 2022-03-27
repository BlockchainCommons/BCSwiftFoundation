import Foundation
import CryptoKit
import URKit
import WolfBase

/// A Schnorr signature.
///
/// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
public struct Signature: Equatable {
    public let data: Data
    public let tag: Data
    
    public init?(data: DataProvider, tag: DataProvider) {
        let data = data.providedData
        guard data.count == 64 else {
            return nil
        }
        self.data = data
        self.tag = tag.providedData
    }
    
    public var description: String {
        "Signature(tag(\(tag.hex))-\(data.hex))"
    }
}

extension Signature {
    public var cbor: CBOR {
        let type = CBOR.unsignedInt(1)
        let sig = CBOR.data(self.data)
        let tag = CBOR.data(self.tag)
        
        return CBOR.array([type, sig, tag])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.signature, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard case let CBOR.array(elements) = cbor else {
            throw CBORError.invalidFormat
        }
        
        guard elements.count == 3 else {
            throw CBORError.invalidFormat
        }
        
        guard
            case let CBOR.unsignedInt(type) = elements[0],
            type == 1,
            case let CBOR.data(sigData) = elements[1],
            case let CBOR.data(tagData) = elements[2],
            let sig = Signature(data: sigData, tag: tagData)
        else {
            throw CBORError.invalidFormat
        }
        
        self = sig
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.signature, cbor) = taggedCBOR else {
            throw CBORError.invalidTag
        }
        try self.init(cbor: cbor)
    }
    
    public init(taggedCBOR: Data) throws {
        try self.init(taggedCBOR: CBOR(taggedCBOR))
    }
}

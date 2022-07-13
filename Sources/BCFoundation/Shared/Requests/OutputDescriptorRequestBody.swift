import Foundation

public struct OutputDescriptorRequestBody {
    public let name: String
    public let useInfo: UseInfo
    public let challenge: Data

    public init(name: String, useInfo: UseInfo, challenge: Data) {
        self.name = name
        self.useInfo = useInfo
        self.challenge = challenge
    }
    
    public var untaggedCBOR: CBOR {
        var a: OrderedMap = [:]
        
        if !name.isEmpty {
            a.append(1, CBOR.utf8String(name))
        }
        
        if !useInfo.isDefault {
            a.append(2, useInfo.taggedCBOR)
        }
        
        a.append(3, CBOR.data(challenge))
        
        return CBOR.orderedMap(a)
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.outputDescriptorRequestBody, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.map(pairs) = untaggedCBOR
        else {
            throw CBORError.invalidFormat
        }
        
        guard
            case let CBOR.utf8String(name) = pairs[1] ?? CBOR.utf8String("")
        else {
            throw CBORError.invalidFormat
        }
        
        let useInfoItem = pairs[2] ?? UseInfo().taggedCBOR
        guard
            let useInfo = try? UseInfo(taggedCBOR: useInfoItem)
        else {
            throw CBORError.invalidFormat
        }
        
        guard
            let challengeItem = pairs[3],
            case let CBOR.data(challenge) = challengeItem,
            challenge.count == 16
        else {
            throw CBORError.invalidFormat
        }
        
        self.name = name
        self.useInfo = useInfo
        self.challenge = challenge
    }

    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.outputDescriptorRequestBody, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

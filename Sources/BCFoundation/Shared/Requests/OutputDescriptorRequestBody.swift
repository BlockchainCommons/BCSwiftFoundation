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
        CBOR.orderedMap([
            1: CBOR.utf8String(name),
            2: useInfo.taggedCBOR,
            3: CBOR.data(challenge)
        ])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.outputDescriptorRequestBody, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.map(pairs) = untaggedCBOR,
            let nameItem = pairs[1],
            case let CBOR.utf8String(name) = nameItem,
            let useInfoItem = pairs[2],
            let useInfo = try? UseInfo(taggedCBOR: useInfoItem),
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

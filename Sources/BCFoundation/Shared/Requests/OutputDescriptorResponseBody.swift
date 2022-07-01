import Foundation

public struct OutputDescriptorResponseBody {
    public let descriptor: OutputDescriptor
    public let challengeSignature: Data
    
    public init(descriptor: OutputDescriptor, challengeSignature: Data) {
        self.descriptor = descriptor
        self.challengeSignature = challengeSignature
    }
    
    public var untaggedCBOR: CBOR {
        CBOR.orderedMap([
            1: CBOR.utf8String(descriptor.sourceWithChecksum),
            2: CBOR.data(challengeSignature)
        ])
    }
    
    public var taggedCBOR: CBOR {
        CBOR.tagged(.outputDescriptorResponseBody, untaggedCBOR)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.map(pairs) = untaggedCBOR,
            let descriptorItem = pairs[1],
            case let CBOR.utf8String(descriptorSource) = descriptorItem,
            let descriptor = try? OutputDescriptor(descriptorSource),
            let challengeSignatureItem = pairs[2],
            case let CBOR.data(challengeSignature) = challengeSignatureItem
        else {
            throw CBORError.invalidFormat
        }
        self.descriptor = descriptor
        self.challengeSignature = challengeSignature
    }

    public init?(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.outputDescriptorResponseBody, untaggedCBOR) = taggedCBOR else {
            return nil
        }
        try self.init(untaggedCBOR: untaggedCBOR)
    }
}

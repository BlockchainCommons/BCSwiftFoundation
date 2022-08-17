import Foundation

public struct OutputDescriptorResponseBody: Equatable {
    public let descriptor: OutputDescriptor
    public let challengeSignature: Data
    
    public init(descriptor: OutputDescriptor, challengeSignature: Data) {
        self.descriptor = descriptor
        self.challengeSignature = challengeSignature
    }
}

public extension OutputDescriptorResponseBody {
    var untaggedCBOR: CBOR {
        [
            CBOR.utf8String(descriptor.sourceWithChecksum),
            CBOR.data(challengeSignature)
        ]
    }
    
    init(untaggedCBOR cbor: CBOR) throws {
        guard
            case let CBOR.array(array) = cbor,
            array.count == 2,
            case let CBOR.utf8String(source) = array[0],
            case let CBOR.data(challengeSignature) = array[1]
        else {
            throw CBORError.invalidFormat
        }
    
        let descriptor = try OutputDescriptor(source)
        self.init(descriptor: descriptor, challengeSignature: challengeSignature)
    }
    
    var taggedCBOR: CBOR {
        CBOR.tagged(.outputDescriptorResponse, untaggedCBOR)
    }
    
    init(taggedCBOR cbor: CBOR) throws {
        guard case CBOR.tagged(.outputDescriptorResponse, let item) = cbor else {
            throw CBORError.invalidTag
        }
        try self.init(untaggedCBOR: item)
    }
}

extension OutputDescriptorResponseBody: CBORCodable {
    public static func cborDecode(_ cbor: CBOR) throws -> OutputDescriptorResponseBody {
        try self.init(taggedCBOR: cbor)
    }
    
    public var cbor: CBOR {
        taggedCBOR
    }
}

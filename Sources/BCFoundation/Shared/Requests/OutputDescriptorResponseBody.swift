import Foundation

public struct OutputDescriptorResponseBody: Equatable {
    public let descriptor: OutputDescriptor
    public let challengeSignature: Data
    
    public init(descriptor: OutputDescriptor, challengeSignature: Data) {
        self.descriptor = descriptor
        self.challengeSignature = challengeSignature
    }
}

extension OutputDescriptorResponseBody: CBORTaggedCodable {
    public static var cborTag: Tag = .outputDescriptorResponse
    
    public var untaggedCBOR: CBOR {
        [ descriptor.sourceWithChecksum, challengeSignature ].cbor
    }
    
    public init(untaggedCBOR cbor: CBOR) throws {
        guard
            case CBOR.array(let array) = cbor,
            array.count == 2,
            let source = try? String(cbor: array[0]),
            let challengeSignature = try? Data(cbor: array[1])
        else {
            throw CBORError.invalidFormat
        }
        let descriptor = try OutputDescriptor(source)
        self.init(descriptor: descriptor, challengeSignature: challengeSignature)
    }
}

extension OutputDescriptorResponseBody: TransactionResponseBody {
    public var envelope: Envelope { Envelope(self) }
}

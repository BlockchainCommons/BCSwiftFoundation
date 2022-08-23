import Foundation
import URKit
import WolfBase

public enum TransactionResponseError: Swift.Error {
    case invalidFormat
    case unknownResponseType
}

public struct TransactionResponse: Equatable {
    public let id: CID
    public let body: Body
    
    public init(id: CID, body: Body) {
        self.id = id
        self.body = body
    }
    
    public enum Body: Equatable {
        case seed(Seed)
        case key(HDKey)
        case psbtSignature(PSBT)
        case outputDescriptor(OutputDescriptorResponseBody)
    }
}

public extension TransactionResponse {
    init(ur: UR) throws {
        switch ur.type {
        case CBOR.Tag.envelope.name!:
            try self.init(untaggedCBOR: CBOR(ur.cbor))
        default:
            throw URError.unexpectedType
        }
    }
    
    init(untaggedCBOR cbor: CBOR) throws {
        let envelope = try Envelope(untaggedCBOR: cbor)
        guard
            let responseItem = envelope.leaf,
            case CBOR.tagged(.response, let idItem) = responseItem
        else {
            throw TransactionResponseError.invalidFormat
        }
        self.id = try CID(taggedCBOR: idItem)
        guard let resultItem = try envelope.extractObject(forPredicate: .result).leaf else {
            throw TransactionResponseError.unknownResponseType
        }
        switch resultItem {
        case CBOR.tagged(.seed, let item):
            self.body = .seed(try Seed(untaggedCBOR: item))
        case CBOR.tagged(.hdKey, let item):
            self.body = .key(try HDKey(untaggedCBOR: item))
        case CBOR.tagged(.psbt, let item):
            self.body = .psbtSignature(try PSBT(untaggedCBOR: item))
        case CBOR.tagged(.outputDescriptorResponse, let item):
            self.body = .outputDescriptor(try OutputDescriptorResponseBody(untaggedCBOR: item))
        default:
            throw TransactionResponseError.unknownResponseType
        }
    }
}

public extension TransactionResponse {
    var envelope: Envelope {
        Envelope(response: id, result: body.envelope)
    }
    
    var ur: UR {
        envelope.ur
    }
}

public extension TransactionResponse.Body {
    var envelope: Envelope {
        switch self {
        case .seed(let seed):
            return Envelope(seed)
        case .key(let key):
            return Envelope(key)
        case .psbtSignature(let psbt):
            return Envelope(psbt)
        case .outputDescriptor(let body):
            return Envelope(body)
        }
    }
}

import Foundation
import URKit
import WolfBase

public enum TransactionResponseError: Swift.Error {
    case invalidFormat
    case unknownResponseType
}

public protocol TransactionResponseBody: Equatable {
    var envelope: Envelope { get }
}

public struct TransactionResponse: Equatable {
    public let id: CID
    public let body: any TransactionResponseBody
    
    public init(id: CID, body: any TransactionResponseBody) {
        self.id = id
        self.body = body
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
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
            self.body = try Seed(untaggedCBOR: item)
        case CBOR.tagged(.hdKey, let item):
            self.body = try HDKey(untaggedCBOR: item)
        case CBOR.tagged(.psbt, let item):
            self.body = try PSBT(untaggedCBOR: item)
        case CBOR.tagged(.outputDescriptorResponse, let item):
            self.body = try OutputDescriptorResponseBody(untaggedCBOR: item)
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

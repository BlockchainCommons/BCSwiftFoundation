import Foundation
import URKit
import WolfBase

public enum TransactionResponseError: Swift.Error {
    case invalidFormat
    case unknownResponseType
}

public struct TransactionResponse: Equatable, Sendable {
    public let id: ARID
    public let result: Envelope
    
    public init(id: ARID, result: EnvelopeEncodable) {
        self.id = id
        self.result = result.envelope
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

extension TransactionResponse: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(response: id, result: result)
    }
    
    public init(envelope: Envelope) throws {
        try self.init(id: envelope.responseID, result: envelope.result())
    }
}

public extension TransactionResponse {
    init(ur: UR) throws {
        switch ur.type {
        case Envelope.cborTag.name!:
            try self.init(envelope: Envelope(untaggedCBOR: ur.cbor))
        default:
            throw URError.unexpectedType
        }
    }
    
    var ur: UR {
        envelope.ur
    }
}

public extension TransactionResponse {
    func parseResult() throws -> any TransactionResponseBody {
        if result.hasType(OutputDescriptorResponseBody.type) {
            return try OutputDescriptorResponseBody(envelope: result)
        } else if result.hasType(HDKey.type) {
            return try HDKey(envelope: result)
        } else if result.hasType(Seed.type) {
            return try Seed(envelope: result)
        } else if result.hasType(PSBT.type) {
            return try PSBT(envelope: result)
        } else {
            throw TransactionResponseError.unknownResponseType
        }
    }
}

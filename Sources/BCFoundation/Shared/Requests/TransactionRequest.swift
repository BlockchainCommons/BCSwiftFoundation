import Foundation
import URKit
import WolfBase
import SecureComponents

public enum TransactionRequestError: Swift.Error {
    case invalidFormat
}

public struct TransactionRequest: Equatable {
    public let id: CID
    public let body: Envelope
    public let function: Function
    public let note: String
    public let date: Date?
    
    public init(id: CID = CID(), body: EnvelopeEncodable, note: String = "", date: Date? = nil) {
        self.id = id
        self.body = body.envelope
        self.function = try! self.body.function
        self.note = note
        self.date = date
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

extension TransactionRequest: EnvelopeCodable {
    public var envelope: Envelope {
        self.envelope(noteLimit: .max)
    }
    
    public init(_ envelope: Envelope) throws {
        let id = try envelope.requestID
        let body = try envelope.requestBody
        let note = try envelope.extractOptionalObject(String.self, forPredicate: .note) ?? ""
        let date = try envelope.extractOptionalObject(Date.self, forPredicate: .date)
        self.init(id: id, body: body, note: note, date: date)
    }
}


public extension TransactionRequest {
    init(psbtCBOR cbor: CBOR) throws {
        let psbt = try PSBT(untaggedCBOR: cbor)
        let body = PSBTSignatureRequestBody(psbt: psbt, isRawPSBT: true)
        self.init(id: CID(), body: body)
    }
}

public extension TransactionRequest {
    init(ur: UR) throws {
        switch ur.type {
        case Envelope.cborTag.name!:
            try self.init(Envelope(untaggedCBOR: ur.cbor))
        case PSBT.cborTag.name!:
            try self.init(psbtCBOR: ur.cbor)
        default:
            throw URError.unexpectedType
        }
    }

    func extractBody<Body: TransactionRequestBody>(_ type: Body.Type) throws -> Body {
        guard function == type.function else {
            throw EnvelopeError.unknownFunction
        }
        return try type.self.init(body)
    }
    
    func parseBody() throws -> any TransactionRequestBody {
        switch function {
        case .getSeed:
            return try SeedRequestBody(body)
        case .getKey:
            return try KeyRequestBody(body)
        case .signPSBT:
            return try PSBTSignatureRequestBody(body)
        case .getOutputDescriptor:
            return try OutputDescriptorRequestBody(body)
        default:
            throw EnvelopeError.unknownFunction
        }
    }
}

public extension TransactionRequest {
    func envelope(noteLimit: Int) -> Envelope {
        let n = note.prefix(count: noteLimit)
        return Envelope(request: id, body: body.envelope)
            .addAssertion(if: !n.isEmpty, .note, n)
            .addAssertion(.date, date)
    }

    var ur: UR {
        envelope.ur
    }

    func sizeLimitedUR(noteLimit: Int = 500) -> UR {
        envelope(noteLimit: noteLimit).ur
    }
}

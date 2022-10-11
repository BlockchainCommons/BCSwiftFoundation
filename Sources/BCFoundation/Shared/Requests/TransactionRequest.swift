import Foundation
import URKit
import WolfBase
import BCSecureComponents

public enum TransactionRequestError: Swift.Error {
    case invalidFormat
    case unknownRequestType
}

public protocol TransactionRequestBody : Equatable {
    var envelope: Envelope { get }
    init(_ envelope: Envelope) throws
}

public struct TransactionRequest: Equatable {
    public let id: CID
    public let body: any TransactionRequestBody
    public let note: String?
    
    public init(id: CID = CID(), body: any TransactionRequestBody, note: String? = nil) {
        self.id = id
        self.body = body
        self.note = note
    }
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id
    }
}

public extension TransactionRequest {
    init(psbtCBOR: Data) throws {
        let cbor = try CBOR(psbtCBOR)
        let psbt = try PSBT(untaggedCBOR: cbor)
        let body = PSBTSignatureRequestBody(psbt: psbt, isRawPSBT: true)
        self.init(id: CID(), body: body, note: nil)
    }
}

public extension TransactionRequest {
    init(ur: UR) throws {
        switch ur.type {
        case CBOR.Tag.envelope.urType:
            try self.init(untaggedCBOR: CBOR(ur.cbor))
        case CBOR.Tag.psbt.urType:
            try self.init(psbtCBOR: ur.cbor)
        default:
            throw URError.unexpectedType
        }
    }
    
    init(untaggedCBOR cbor: CBOR) throws {
        let envelope = try Envelope(untaggedCBOR: cbor)
        guard
            let requestItem = envelope.leaf,
            case CBOR.tagged(.request, let idItem) = requestItem
        else {
            throw TransactionRequestError.invalidFormat
        }
        self.id = try CID(taggedCBOR: idItem)
        self.note = try? envelope.extractObject(String.self, forPredicate: .note)
        let bodyEnvelope = try envelope.extractObject(forPredicate: .body)
        let function = try bodyEnvelope.extractSubject(FunctionIdentifier.self)
        switch function {
        case .getSeed:
            self.body = try SeedRequestBody(bodyEnvelope)
        case .getKey:
            self.body = try KeyRequestBody(bodyEnvelope)
        case .signPSBT:
            self.body = try PSBTSignatureRequestBody(bodyEnvelope)
        case .getOutputDescriptor:
            self.body = try OutputDescriptorRequestBody(bodyEnvelope)
        default:
            throw TransactionRequestError.unknownRequestType
        }
    }
}

public extension TransactionRequest {
    func envelope(noteLimit: Int = .max) -> Envelope {
        let n = (note ?? "").prefix(count: noteLimit)
        return Envelope(request: id, body: body.envelope)
            .addAssertion(if: !n.isEmpty, .note, n)
    }
    
    var ur: UR {
        envelope().ur
    }
    
    func sizeLimitedUR(noteLimit: Int = 500) -> UR {
        envelope(noteLimit: noteLimit).ur
    }
}

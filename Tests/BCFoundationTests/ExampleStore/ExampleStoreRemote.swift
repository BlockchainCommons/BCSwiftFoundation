import Foundation
import BCFoundation
import WolfBase

public extension ExampleStore {
    static func makeRequest(_ body: StoreRequestBody, accountPrivateKey: PrivateKeyBase, transactionID: ARID? = nil) -> Envelope {
        let transactionID = transactionID ?? ARID()
        let request = TransactionRequest(id: transactionID, body: body, date: Date()).envelope
        return try! request
            .wrap()
            .sign(with: accountPrivateKey)
            .encryptSubject(to: ExampleStore.publicKey)
    }

    static func parseRequest(_ request: Envelope) throws -> ((TransactionRequest, any StoreRequestBody))? {
        let decryptedRequest = try request
            .decrypt(to: privateKey)
            .unwrap()
        
        let transactionRequest = try TransactionRequest(envelope: decryptedRequest)
        let body: (any StoreRequestBody)?
        switch transactionRequest.function {
        case StoreShareRequestBody.function:
            body = try StoreShareRequestBody(envelope: transactionRequest.body)
        case UpdateFallbackRequestBody.function:
            body = try UpdateFallbackRequestBody(envelope: transactionRequest.body)
        case RetrieveFallbackRequestBody.function:
            body = try RetrieveFallbackRequestBody(envelope: transactionRequest.body)
        case UpdatePublicKeyRequestBody.function:
            let b = try UpdatePublicKeyRequestBody(envelope: transactionRequest.body)
            try request.verifySignature(from: b.newPublicKey)
            body = b
        case RetrieveSharesRequestBody.function:
            body = try RetrieveSharesRequestBody(envelope: transactionRequest.body)
        case DeleteSharesRequestBody.function:
            body = try DeleteSharesRequestBody(envelope: transactionRequest.body)
        case FallbackTransferRequestBody.function:
            body = try FallbackTransferRequestBody(envelope: transactionRequest.body)
        case DeleteAccountRequestBody.function:
            body = try DeleteAccountRequestBody(envelope: transactionRequest.body)
        default:
            body = nil
        }

        guard let body else {
            return nil
        }
        
        print("\n=== Received Request ===")
        print(decryptedRequest.format)

        return (transactionRequest, body)
    }
    
    static func validateRequest(_ requestEnvelope: Envelope, _ transactionRequest: TransactionRequest) throws {
        let (_, body) = try ExampleStore.parseRequest(requestEnvelope)!
        
        try requestEnvelope.verifySignature(from: body.publicKey)
        
        guard let transactionDate = transactionRequest.date else {
            throw Error.expiredRequest
        }
        
        let elapsedTime = Date.timeIntervalSinceReferenceDate - transactionDate.timeIntervalSinceReferenceDate
        guard elapsedTime <= Self.requestExpiry else {
            throw Error.expiredRequest
        }
    }
    
    func handleRequest(_ requestEnvelope: Envelope) -> Envelope {
        var transactionID: ARID!
        var response: Envelope!
        do {
            guard let (transactionRequest, requestBody) = try Self.parseRequest(requestEnvelope) else {
                throw EnvelopeError.unknownFunction
            }
            transactionID = transactionRequest.id
            try Self.validateRequest(requestEnvelope, transactionRequest)
            switch requestBody {
            case let body as StoreShareRequestBody:
                let receipt = try storeShare(publicKey: body.publicKey, payload: body.payload)
                response = Envelope(response: transactionID, result: receipt)
            case let body as UpdateFallbackRequestBody:
                try updateFallback(publicKey: body.publicKey, fallback: body.fallback)
                response = Envelope(response: transactionID)
            case let body as RetrieveFallbackRequestBody:
                guard let fallback = try retrieveFallback(publicKey: body.publicKey) else {
                    throw Error.noFallback
                }
                response = Envelope(response: transactionID, result: fallback)
            case let body as UpdatePublicKeyRequestBody:
                try updatePublicKey(old: body.publicKey, new: body.newPublicKey)
                response = Envelope(response: transactionID)
            case let body as RetrieveSharesRequestBody:
                let receiptShares = try retrieveShares(publicKey: body.publicKey, receipts: body.receipts)
                response = Envelope(response: transactionID, results: Array(receiptShares.values))
            case let body as DeleteSharesRequestBody:
                try deleteShares(publicKey: body.publicKey, receipts: body.receipts)
                response = Envelope(response: transactionID)
            case let body as FallbackTransferRequestBody:
                try fallbackTransfer(fallback: body.fallback, new: body.publicKey)
                response = Envelope(response: transactionID, result: KnownValue.Processing)
            case let body as DeleteAccountRequestBody:
                deleteAccount(publicKey: body.publicKey)
                response = Envelope(response: transactionID)
            default:
                throw EnvelopeError.unknownFunction
            }
        } catch {
            if let transactionID {
                response = Envelope(response: transactionID, error: error.localizedDescription)
            } else {
                response = Envelope(error: error.localizedDescription)
            }
        }

        print("\n=== Response ===")
        print(response.format)

        return response
    }
}

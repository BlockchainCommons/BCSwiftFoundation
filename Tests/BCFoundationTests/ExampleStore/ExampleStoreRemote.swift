import Foundation
import BCFoundation
import WolfBase

public extension ExampleStore {
    static func makeRequest(_ body: StoreRequestBody, accountPrivateKey: PrivateKeyBase, transactionID: CID? = nil) -> Envelope {
        let transactionID = transactionID ?? CID()
        let request = TransactionRequest(id: transactionID, body: body, date: Date()).envelope
        return try! request
            .wrap()
            .sign(with: accountPrivateKey)
            .encryptSubject(to: ExampleStore.publicKey)
    }

    static func parseRequest(_ request: Envelope) throws -> TransactionRequest {
        let decryptedRequest = try request
            .decrypt(to: privateKey)
            .unwrap()

        let transactionRequest = try TransactionRequest(decryptedRequest) { bodyEnvelope in
            let function = try bodyEnvelope.extractSubject(Function.self)
            switch function {
            case StoreShareRequestBody.function:
                return try StoreShareRequestBody(bodyEnvelope)
            case UpdateFallbackRequestBody.function:
                return try UpdateFallbackRequestBody(bodyEnvelope)
            case RetrieveFallbackRequestBody.function:
                return try RetrieveFallbackRequestBody(bodyEnvelope)
            case UpdatePublicKeyRequestBody.function:
                let body = try UpdatePublicKeyRequestBody(bodyEnvelope)
                try request.verifySignature(from: body.newPublicKey)
                return body
            case RetrieveSharesRequestBody.function:
                return try RetrieveSharesRequestBody(bodyEnvelope)
            case DeleteSharesRequestBody.function:
                return try DeleteSharesRequestBody(bodyEnvelope)
            case FallbackTransferRequestBody.function:
                return try FallbackTransferRequestBody(bodyEnvelope)
            case DeleteAccountRequestBody.function:
                return try DeleteAccountRequestBody(bodyEnvelope)
            default:
                return nil
            }
        }
        
        print("\n=== Received Request ===")
        print(decryptedRequest.format)

        return transactionRequest
    }
    
    static func validateRequest(_ request: Envelope, _ transactionRequest: TransactionRequest) throws {
        let body = transactionRequest.body as! StoreRequestBody
        
        try request.verifySignature(from: body.publicKey)
        
        guard let transactionDate = transactionRequest.date else {
            throw Error.expiredRequest
        }
        
        let elapsedTime = Date.timeIntervalSinceReferenceDate - transactionDate.timeIntervalSinceReferenceDate
        guard elapsedTime <= Self.requestExpiry else {
            throw Error.expiredRequest
        }
    }
    
    func handleRequest(_ requestEnvelope: Envelope) -> Envelope {
        var transactionID: CID!
        var response: Envelope!
        do {
            let request = try Self.parseRequest(requestEnvelope)
            transactionID = request.id
            try Self.validateRequest(requestEnvelope, request)
            switch request.body {
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
                response = Envelope(response: transactionID, result: KnownValue.processing)
            case let body as DeleteAccountRequestBody:
                deleteAccount(publicKey: body.publicKey)
                response = Envelope(response: transactionID)
            default:
                throw TransactionRequestError.unknownRequestType
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

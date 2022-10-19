import Foundation
import BCFoundation

public struct RetrieveSharesRequestBody: StoreRequestBody {
    public static var function: FunctionIdentifier = "retrieveShares"
    public let publicKey: PublicKeyBase
    public let receipts: Set<Receipt>
    
    public init(publicKey: PublicKeyBase, receipts: Set<Receipt>) {
        self.publicKey = publicKey
        self.receipts = receipts
    }
    
    public init(_ envelope: Envelope) throws {
        guard try envelope.extractSubject(FunctionIdentifier.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "publicKey")
        self.receipts = Set(try envelope.extractObjects(Receipt.self, forParameter: "receipt"))
    }
    
    public var envelope: Envelope {
        var e = Envelope(function: Self.function)
            .addParameter("publicKey", value: publicKey)
        
        for receipt in receipts {
            e = e.addParameter("receipt", value: receipt)
        }
        
        return e
    }
    
    public static func makeRequest(accountPrivateKey: PrivateKeyBase, receipts: Set<Receipt> = [], transactionID: CID? = nil) -> Envelope {
        let body = RetrieveSharesRequestBody(publicKey: accountPrivateKey.publicKeys, receipts: receipts)
        return ExampleStore.makeRequest(body, accountPrivateKey: accountPrivateKey, transactionID: transactionID)
    }
}

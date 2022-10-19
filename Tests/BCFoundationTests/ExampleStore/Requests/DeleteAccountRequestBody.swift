import Foundation
import BCFoundation

public struct DeleteAccountRequestBody: StoreRequestBody {
    public static var function: FunctionIdentifier = "deleteAccount"
    public let publicKey: PublicKeyBase
    
    public init(publicKey: PublicKeyBase) {
        self.publicKey = publicKey
    }
    
    public init(_ envelope: Envelope) throws {
        guard try envelope.extractSubject(FunctionIdentifier.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "publicKey")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("publicKey", value: publicKey)
    }
    
    public static func makeRequest(accountPrivateKey: PrivateKeyBase, transactionID: CID? = nil) -> Envelope {
        let body = DeleteAccountRequestBody(publicKey: accountPrivateKey.publicKeys)
        return ExampleStore.makeRequest(body, accountPrivateKey: accountPrivateKey, transactionID: transactionID)
    }
}
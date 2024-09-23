import Foundation
import BCFoundation

public struct DeleteAccountRequestBody: StoreRequestBody {
    public static let function: Function = "deleteAccount"
    public let publicKey: PublicKeyBase
    
    public init(publicKey: PublicKeyBase) {
        self.publicKey = publicKey
    }
    
    public init(envelope: Envelope) throws {
        guard try envelope.extractSubject(Function.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "publicKey")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("publicKey", value: publicKey)
    }
    
    public static func makeRequest(accountPrivateKey: PrivateKeyBase, transactionID: ARID? = nil) -> Envelope {
        let body = DeleteAccountRequestBody(publicKey: accountPrivateKey.publicKeys)
        return ExampleStore.makeRequest(body, accountPrivateKey: accountPrivateKey, transactionID: transactionID)
    }
}

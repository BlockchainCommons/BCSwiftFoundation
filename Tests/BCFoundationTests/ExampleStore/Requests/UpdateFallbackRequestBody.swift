import Foundation
import BCFoundation

public struct UpdateFallbackRequestBody: StoreRequestBody {
    public static var function: FunctionIdentifier = "updateFallback"
    public let publicKey: PublicKeyBase
    public let fallback: String?

    public init(publicKey: PublicKeyBase, fallback: String?) {
        self.publicKey = publicKey
        self.fallback = fallback
    }
    
    public init(_ envelope: Envelope) throws {
        guard try envelope.extractSubject(FunctionIdentifier.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "publicKey")
        self.fallback = try envelope.extractObject(String.self, forParameter: "fallback")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("publicKey", value: publicKey)
            .addParameter("fallback", value: fallback)
    }
    
    public static func makeRequest(accountPrivateKey: PrivateKeyBase, fallback: String?, transactionID: CID? = nil) -> Envelope {
        let body = UpdateFallbackRequestBody(publicKey: accountPrivateKey.publicKeys, fallback: fallback)
        return ExampleStore.makeRequest(body, accountPrivateKey: accountPrivateKey, transactionID: transactionID)
    }
}

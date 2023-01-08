import Foundation
import BCFoundation

public struct FallbackTransferRequestBody: StoreRequestBody {
    public static var function: Envelope.FunctionIdentifier = "fallbackTransfer"
    public let fallback: String
    public let publicKey: PublicKeyBase

    public init(fallback: String, newPublicKey: PublicKeyBase) {
        self.fallback = fallback
        self.publicKey = newPublicKey
    }
    
    public init(_ envelope: Envelope) throws {
        guard try envelope.extractSubject(Envelope.FunctionIdentifier.self) == Self.function else {
            throw GeneralError("Incorrect function.")
        }
        self.fallback = try envelope.extractObject(String.self, forParameter: "fallback")
        self.publicKey = try envelope.extractObject(PublicKeyBase.self, forParameter: "new")
    }
    
    public var envelope: Envelope {
        Envelope(function: Self.function)
            .addParameter("fallback", value: fallback)
            .addParameter("new", value: publicKey)
    }
    
    public static func makeRequest(fallback: String, newPrivateKey: PrivateKeyBase, transactionID: CID? = nil) -> Envelope {
        let body = FallbackTransferRequestBody(fallback: fallback, newPublicKey: newPrivateKey.publicKeys)
        return ExampleStore.makeRequest(body, accountPrivateKey: newPrivateKey, transactionID: transactionID)
    }
}

import Foundation
import SecureComponents
import Envelope

extension PublicKeyBase: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(self)
    }
    
    public init(envelope: Envelope) throws {
        self = try envelope.extractSubject(Self.self)
    }
}

import Foundation

@frozen
public enum KeyType: Identifiable, CaseIterable, Equatable {
    case `private`
    case `public`
}

public extension KeyType {
    init(isPrivate: Bool) {
        self = isPrivate ? .private : .public
    }

    var id: String {
        switch self {
        case .private:
            return "keytype-private"
        case .public:
            return "keytype-public"
        }
    }

    var name: String {
        switch self {
        case .private:
            return "Private"
        case .public:
            return "Public"
        }
    }
    
    var isPrivate: Bool {
        switch self {
        case .private:
            return true
        case .public:
            return false
        }
    }
}

extension KeyType: EnvelopeCodable {
    public var envelope: Envelope {
        switch self {
        case .private:
            return Envelope(.PrivateKey)
        case .public:
            return Envelope(.PublicKey)
        }
    }
    
    public init(envelope: Envelope) throws {
        guard let v = envelope.subject.knownValue else {
            throw EnvelopeError.invalidFormat
        }
        switch v {
        case .PublicKey:
            self = .public
        case .PrivateKey:
            self = .private
        default:
            throw EnvelopeError.invalidFormat
        }
    }
}

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
            return Envelope(.privateKey)
        case .public:
            return Envelope(.publicKey)
        }
    }
    
    public init(_ envelope: Envelope) throws {
        guard let v = envelope.subject.knownValue else {
            throw EnvelopeError.invalidFormat
        }
        switch v {
        case .publicKey:
            self = .public
        case .privateKey:
            self = .private
        default:
            throw EnvelopeError.invalidFormat
        }
    }
}

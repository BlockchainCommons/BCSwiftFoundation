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

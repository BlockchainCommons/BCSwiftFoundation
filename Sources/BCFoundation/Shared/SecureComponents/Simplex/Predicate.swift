import Foundation

public enum Predicate: UInt64 {
    case id = 1
    case isA = 2
    case authenticatedBy = 3
    case hasRecipient = 4
    case sskrShare = 5
    case controller = 6
    case publicKeys = 7
    case dereferenceVia = 8
}

import Foundation

public enum Predicate: UInt64 {
    case id = 1
    case isA
    case authenticatedBy
    case madeBy
    case hasRecipient
    case sskrShare
    case controller
    case publicKeys
    case dereferenceVia
    case entity
    case hasName
    case language
}

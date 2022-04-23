import Foundation

public enum Predicate: UInt64 {
    case id = 1
    case isA
    case verifiedBy
    case note
    case hasRecipient
    case sskrShare
    case controller
    case publicKeys
    case dereferenceVia
    case entity
    case hasName
    case language
    case issuer
    case holder
}

import Foundation

public enum SimplexError: Error {
    case invalidOperation
    case invalidKey
    case invalidDigest
    case invalidSignature
    case invalidFormat
    case invalidRecipient
    case invalidShares
}

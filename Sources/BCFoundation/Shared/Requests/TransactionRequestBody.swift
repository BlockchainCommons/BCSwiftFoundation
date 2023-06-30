import Foundation

public protocol TransactionRequestBody: EnvelopeCodable {
    static var function: Function { get }
}

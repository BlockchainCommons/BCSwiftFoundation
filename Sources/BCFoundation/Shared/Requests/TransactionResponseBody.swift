import Foundation

public protocol TransactionResponseBody: EnvelopeCodable {
    static var type: Envelope { get }
}

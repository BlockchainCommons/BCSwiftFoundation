import Foundation

public struct Predicate {
    public static let authenticatedBy = Simplex(1)
    
    public static func authenticatedBy(signature: Signature) -> Assertion {
        Assertion(predicate: authenticatedBy, object: Simplex(plaintext: signature))
    }
}

import Foundation
import WolfBase
import class CryptoSwift.Scrypt

/// A secure derivation scheme from a user-defined password to identity data.
///
/// Implemented using Scrypt.
///
/// https://datatracker.ietf.org/doc/html/rfc7914
public class Password: IdentityDataProvider {
    public let data: Data
    public let salt: Data
    
    public static let defaulDKLen = 32
    public static let defaultN = 8192
    public static let defaultR = 8
    public static let defaultP = 1

    public init?(_ password: DataProvider, salt: DataProvider? = nil, dkLen: Int = defaulDKLen, N: Int = defaultN, r: Int = defaultR, p: Int = defaultP) {
        let password = password.providedData
        guard !password.isEmpty else {
            return nil
        }
        let salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
        self.data = try! Data(Scrypt(password: password.bytes, salt: salt.bytes, dkLen: dkLen, N: N, r: r, p: p).calculate())
        self.salt = salt
    }
    
    public func validate(_ password: String, dkLen: Int = defaulDKLen, N: Int = defaultN, r: Int = defaultR, p: Int = defaultP) -> Bool {
        guard !password.isEmpty else {
            return false
        }
        let d = try! Data(Scrypt(password: password.utf8Data.bytes, salt: salt.bytes, dkLen: dkLen, N: N, r: r, p: p).calculate())
        return data == d
    }
    
    public var identityData: Data {
        data
    }
}

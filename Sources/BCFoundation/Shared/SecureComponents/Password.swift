import Foundation
import WolfBase
import class CryptoSwift.Scrypt

/// A secure derivation scheme from a user-provided password to identity data.
///
/// Implemented using Scrypt.
///
/// https://datatracker.ietf.org/doc/html/rfc7914
public class Password: IdentityDataProvider {
    public let n: Int
    public let r: Int
    public let p: Int
    public let salt: Data
    public let data: Data

    public static let defaultN = 8192
    public static let defaultR = 8
    public static let defaultP = 1
    public static let defaulDKLen = 32

    public init(n: Int, r: Int, p: Int, salt: Data, data: Data) {
        self.n = n
        self.r = r
        self.p = p
        self.salt = salt
        self.data = data
    }

    public init?(_ password: DataProvider, n: Int = defaultN, r: Int = defaultR, p: Int = defaultP, salt: DataProvider? = nil, dkLen: Int = defaulDKLen) {
        self.n = n
        self.r = r
        self.p = p

        let salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
        self.salt = salt

        let password = password.providedData
        guard !password.isEmpty else {
            return nil
        }
        self.data = try! Data(Scrypt(password: password.bytes, salt: salt.bytes, dkLen: dkLen, N: n, r: r, p: p).calculate())
    }
    
    public func validate(_ password: String) -> Bool {
        guard !password.isEmpty else {
            return false
        }
        let d = try! Data(Scrypt(password: password.utf8Data.bytes, salt: salt.bytes, dkLen: data.count, N: n, r: r, p: p).calculate())
        return data == d
    }
    
    public var identityData: Data {
        data
    }
}

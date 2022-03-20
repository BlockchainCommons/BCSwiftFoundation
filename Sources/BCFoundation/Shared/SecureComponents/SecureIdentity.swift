import Foundation
import CryptoKit
import WolfBase

public struct SecureIdentity {
    let identityData: Data
    let salt: Data
    
    public init(_ dataProvider: SecureIdentityDataProvider, salt: DataProvider? = nil) {
        self.identityData = dataProvider.identityData
        self.salt = salt?.providedData ?? SecureRandomNumberGenerator.shared.data(count: 16)
    }
    
    public init() {
        self.init(SecureRandomNumberGenerator.shared.data(count: 32))
    }
    
    public var signingPrivateKey: PrivateSigningKey {
        return .init(rawValue: HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: identityData), salt: salt, info: "signing".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var signingPublicKey: PublicSigningKey {
        .init(signingPrivateKey)
    }
    
    public var agreementPrivateKey: PrivateAgreementKey {
        return .init(rawValue: HKDF<SHA512>.deriveKey(inputKeyMaterial: .init(data: identityData), salt: salt, info: "agreement".utf8Data, outputByteCount: 32)
            .withUnsafeBytes { Data($0) })!
    }
    
    public var agreementPublicKey: PublicAgreementKey {
        .init(agreementPrivateKey)
    }
}

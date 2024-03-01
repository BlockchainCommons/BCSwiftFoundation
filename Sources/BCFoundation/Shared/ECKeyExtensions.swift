import Foundation

public extension SecP256K1PublicKey {
    func address(version: UInt8) -> String {
        var hash = hash160
        hash.insert(version, at: 0)
        return hash.base58(isCheck: true)
    }
    
    func address(useInfo: UseInfo, isSH: Bool) -> String {
        address(version: isSH ? useInfo.versionSH : useInfo.versionPKH)
    }
}

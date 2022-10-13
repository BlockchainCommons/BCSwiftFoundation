import BCFoundation

public protocol StoreRequestBody: TransactionRequestBody {
    var publicKey: PublicKeyBase { get }
}

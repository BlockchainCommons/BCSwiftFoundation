import BCFoundation
import WolfBase
import XCTest

/// An implementation of a skeletal share store, which is a service that could be
/// used to back up SSKR shares and similar non-confidential information that might
/// be used for social recovery schemes.
public class ExampleStore {
    static let maxPayloadSize = 1000
    static let privateKey = PrivateKeyBase()
    static let publicKey = privateKey.publicKeys

    public enum Error: LocalizedError {
        case unknownReceipt
        case userMismatch
        case unknownPublicKey
        case payloadTooLarge
        case fallbackAlreadyInUse
        case invalidFallback
        case publicKeyAlreadyInUse
        case expiredRequest
        case noFallback
        
        public var errorDescription: String? {
            switch self {
            case .unknownReceipt:
                return "unknownReceipt"
            case .userMismatch:
                return "userMismatch"
            case .unknownPublicKey:
                return "unknownPublicKey"
            case .payloadTooLarge:
                return "payloadTooLarge"
            case .fallbackAlreadyInUse:
                return "fallbackAlreadyInUse"
            case .invalidFallback:
                return "invalidFallback"
            case .publicKeyAlreadyInUse:
                return "publicKeyAlreadyInUse"
            case .expiredRequest:
                return "expiredRequest"
            case .noFallback:
                return "noFallback"
            }
        }
    }

    struct User {
        // The userID is for internal use only, and never changes for a given account.
        // Users always identify themselves by a public key, which can change over the
        // lifetime of the account.
        let userID: CID
        var publicKey: PublicKeyBase
        var fallback: String? = nil
    }
    
    struct Record: Hashable {
        let userID: CID
        let payload: Data
        let receipt: Receipt
        
        init(userID: CID, payload: Data) {
            self.userID = userID
            self.payload = payload
            self.receipt = Receipt(userID: userID, payload: payload)
        }
    }
    
    var usersByID: [CID: User] = [:]
    var userIDsByFallback: [String: CID] = [:]
    var userIDsByPublicKey: [PublicKeyBase: CID] = [:]
    var recordsByReceipt: [Receipt: Record] = [:]
    var receiptsByUserID: [CID: Set<Receipt>] = [:]
}

extension ExampleStore.Record: CustomStringConvertible {
    var description: String {
        "Record(userID: \(userID), payload: \(payload.hex), receipt: \(receipt))"
    }
}

extension ExampleStore {
    func record(userID: CID, receipt: Receipt) throws -> Record? {
        guard let record = recordsByReceipt[receipt] else {
            return nil
        }
        guard record.userID == userID else {
            throw Error.userMismatch
        }
        return record
    }
    
    func getUserID(for publicKey: PublicKeyBase) throws -> CID {
        guard let userID = userIDsByPublicKey[publicKey] else {
            throw Error.unknownPublicKey
        }
        return userID
    }
    
    func delete(record: Record) throws {
        let receipt = record.receipt
        receiptsByUserID[record.userID]!.remove(receipt)
        recordsByReceipt.removeValue(forKey: receipt)
    }
}

extension ExampleStore: CustomStringConvertible {
    public var description: String {
        "ExampleStore(usersByID: \(usersByID), userIDsByPublicKey: \(userIDsByPublicKey), recordsByReceipt: \(recordsByReceipt), receiptsByUserID: \(receiptsByUserID))"
    }
}

/// This is the Swift interface of the `ExampleStore` public API; it is primarily
/// called indirectly by the distributed function call API (forthcoming) which
/// handles authentication of the public keys on incoming requests. So by the time
/// any of these functions are called, the caller must have already proved by
/// signature that they control the corresponding private key.
public protocol ExampleStoreProtocol {
    /// This is a Trust-On-First-Use (TOFU) function. If the provided public key is not
    /// recognized, then a new account is created and the provided payload is stored in
    /// it. It is also used to add additional shares to an existing account. Adding an
    /// already existing share to an account is idempotent.
    func storeShare(publicKey: PublicKeyBase, payload: Data) throws -> Receipt
    
    /// Updates an account's fallback contact method, which could be a phone
    /// number, email address, or similar. The fallback is used to give users a way to
    /// change their public key in the event they lose it. It is up to ExampleStore's
    /// owner to validate the fallback contact method before letting the public key be
    /// changed.
    func updateFallback(publicKey: PublicKeyBase, fallback: String?) throws

    /// Retrieves an account's fallback contact method, if any.
    func retrieveFallback(publicKey: PublicKeyBase) throws -> String?
    
    /// Changes the public key used as the account identifier. It could be invoked
    /// specifically because a user requests it, in which case they will need to know
    /// their old public key, or it could be invoked because they used their fallback
    /// contact method to request a transfer token that encodes their old public key.
    func updatePublicKey(old: PublicKeyBase, new: PublicKeyBase) throws

    /// Deletes either a subset of shares a user controls, or all the shares if a
    /// subset of receipts is not provided. Deletes are idempotent; in other words,
    /// deleting nonexistent shares is not an error.
    func deleteShares(publicKey: PublicKeyBase, receipts: Set<Receipt>?) throws

    /// Returns a dictionary of `[Receipt: Payload]` corresponding to the set of
    /// input receipts, or corresponding to all the controlled shares if no input
    /// receipts are provided. Attempting to retrieve nonexistent receipts or receipts
    /// from the wrong account is an error.
    func retrieveShares(publicKey: PublicKeyBase, receipts: Set<Receipt>) throws -> [Receipt: Data]
    
    /// Deletes all the shares of an account and any other data associated with it, such
    /// as the fallback contact method. Deleting an account is idempotent; in other words,
    /// deleting a nonexistent account is not an error.
    func deleteAccount(publicKey: PublicKeyBase)
    
    /// Requests a reset of the account's public key without knowing the current one.
    /// The account must have a validated fallback contact method that matches the one
    /// provided. The Store owner needs to then contact the user via their fallback
    /// contact method to confirm the change. If the request is not confirmed by a set
    /// amount of time, then the change is not made.
    func fallbackTransfer(fallback: String, new: PublicKeyBase) throws
}

extension ExampleStore: ExampleStoreProtocol {
    public func storeShare(publicKey: PublicKeyBase, payload: Data) throws -> Receipt {
        var userID: CID! = userIDsByPublicKey[publicKey]
        if userID == nil {
            userID = CID()
            usersByID[userID] = User(userID: userID, publicKey: publicKey)
            userIDsByPublicKey[publicKey] = userID
            receiptsByUserID[userID] = []
        }
        guard payload.count <= Self.maxPayloadSize else {
            throw Error.payloadTooLarge
        }
        let record = Record(userID: userID, payload: payload)
        let receipt = record.receipt
        recordsByReceipt[receipt] = record
        receiptsByUserID[userID]!.insert(receipt)
        return receipt
    }
    
    public func updateFallback(publicKey: PublicKeyBase, fallback: String?) throws {
        let userID = try getUserID(for: publicKey)
        if let fallback {
            guard userIDsByFallback[fallback] == nil else {
                throw Error.fallbackAlreadyInUse
            }
        }
        with(&usersByID[userID]!) { user in
            if let oldFallback = user.fallback {
                userIDsByFallback.removeValue(forKey: oldFallback)
            }
            user.fallback = fallback
            if let fallback {
                userIDsByFallback[fallback] = userID
            }
        }
    }
    
    public func retrieveFallback(publicKey: PublicKeyBase) throws -> String? {
        try usersByID[getUserID(for: publicKey)]?.fallback
    }
    
    public func updatePublicKey(old: PublicKeyBase, new: PublicKeyBase) throws {
        guard userIDsByPublicKey[new] == nil else {
            throw Error.publicKeyAlreadyInUse
        }
        let userID = try getUserID(for: old)
        userIDsByPublicKey.removeValue(forKey: old)
        userIDsByPublicKey[new] = userID
        with(&usersByID[userID]!) { user in
            user.publicKey = new
        }
    }
    
    public func deleteShares(publicKey: PublicKeyBase, receipts: Set<Receipt>? = nil) throws {
        let userID = try getUserID(for: publicKey)
        let receipts = receipts ?? receiptsByUserID[userID]!
        let records = try receipts.compactMap { try record(userID: userID, receipt: $0 ) }
        for record in records {
            try delete(record: record)
        }
    }
    
    public func retrieveShares(publicKey: PublicKeyBase, receipts: Set<Receipt> = []) throws -> [Receipt: Data] {
        let userID = try getUserID(for: publicKey)
        let receipts = receipts.isEmpty ? receiptsByUserID[userID]! : receipts
        return try receipts.reduce(into: [:]) { result, receipt in
            guard let record = try record(userID: userID, receipt: receipt ) else {
                throw Error.unknownReceipt
            }
            result[receipt] = record.payload
        }
    }
    
    public func deleteAccount(publicKey: PublicKeyBase) {
        guard let userID = try? getUserID(for: publicKey) else {
            return
        }
        try! deleteShares(publicKey: publicKey)
        userIDsByPublicKey.removeValue(forKey: publicKey)
        usersByID.removeValue(forKey: userID)
    }
    
    public func fallbackTransfer(fallback: String, new: PublicKeyBase) throws {
        guard userIDsByPublicKey[new] == nil else {
            throw Error.publicKeyAlreadyInUse
        }
        guard userIDsByFallback[fallback] != nil else {
            throw Error.invalidFallback
        }
        // Here the store must initiate asyncronously using the fallback to verify the
        // user's intent to change their key and only change it if the verification
        // succeeds.
    }
}

public extension ExampleStore {
    /// Convenience method for deleting a single share
    func deleteShare(publicKey: PublicKeyBase, receipt: Receipt) throws {
        try deleteShares(publicKey: publicKey, receipts: Set([receipt]))
    }

    /// Convenience method for retriving a single share
    func retrieveShare(publicKey: PublicKeyBase, receipt: Receipt) throws -> Data {
        try retrieveShares(publicKey: publicKey, receipts: Set([receipt])).first!.1
    }
}

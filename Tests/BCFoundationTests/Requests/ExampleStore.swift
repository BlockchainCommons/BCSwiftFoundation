import BCFoundation
import WolfBase
import XCTest

public struct Receipt: Hashable {
    let data: Data
    
    init(userID: CID, payload: Data) {
        self.data = Digest(userID.data + payload).data
    }
}

extension Receipt: CustomStringConvertible {
    public var description: String {
        "Receipt(\(data.hex))"
    }
}

/// An implementation of a skeletal share store, which is a service that could be
/// used to back up SSKR shares and similar non-confidential information that might
/// be used for social recovery schemes.
public class ExampleStore {
    static let maxPayloadSize = 1000

    public enum Error: Swift.Error {
        case unknownReceipt
        case userMismatch
        case unknownPublicKey
        case payloadTooLarge
    }

    struct User {
        let id: CID
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
    func retrieveShares(publicKey: PublicKeyBase, receipts: Set<Receipt>?) throws -> [Receipt: Data]
    
    /// Deletes all the shares of an account and any other data associated with it, such
    /// as the fallback contact method. Deleting an account is idempotent; in other words,
    /// deleting a nonexistent account is not an error.
    func deleteAccount(publicKey: PublicKeyBase)
}

extension ExampleStore: ExampleStoreProtocol {
    public func storeShare(publicKey: PublicKeyBase, payload: Data) throws -> Receipt {
        var userID: CID! = userIDsByPublicKey[publicKey]
        if userID == nil {
            userID = CID()
            usersByID[userID] = User(id: userID)
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
        with(&usersByID[userID]!) { user in
            user.fallback = fallback
        }
    }
    
    public func retrieveFallback(publicKey: PublicKeyBase) throws -> String? {
        try usersByID[getUserID(for: publicKey)]?.fallback
    }

    public func updatePublicKey(old: PublicKeyBase, new: PublicKeyBase) throws {
        let userID = try getUserID(for: old)
        userIDsByPublicKey.removeValue(forKey: old)
        userIDsByPublicKey[new] = userID
    }

    public func deleteShares(publicKey: PublicKeyBase, receipts: Set<Receipt>? = nil) throws {
        let userID = try getUserID(for: publicKey)
        let receipts = receipts ?? receiptsByUserID[userID]!
        let records = try receipts.compactMap { try record(userID: userID, receipt: $0 ) }
        for record in records {
            try delete(record: record)
        }
    }

    public func retrieveShares(publicKey: PublicKeyBase, receipts: Set<Receipt>? = nil) throws -> [Receipt: Data] {
        let userID = try getUserID(for: publicKey)
        let receipts = receipts ?? receiptsByUserID[userID]!
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

class ExampleStoreTests: XCTestCase {
    func testStore() throws {
        let exampleStore = ExampleStore()

        // Alice stores a share
        let alicePublicKey = PrivateKeyBase().publicKeys
        let alicePayload1 = ‡"cafebabe"
        let aliceReceipt1 = try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload1)
        
        // Bob stores a share
        let bobPublicKey = PrivateKeyBase().publicKeys
        let bobPayload1 = ‡"deadbeef"
        let bobReceipt1 = try exampleStore.storeShare(publicKey: bobPublicKey, payload: bobPayload1)
        
        // Alice retrieves her share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: alicePublicKey, receipt: aliceReceipt1), alicePayload1)
        
        // Bob retrieves his share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: bobReceipt1), bobPayload1)
        
        // Alice stores a second share
        let alicePayload2 = ‡"cafef00d"
        let aliceReceipt2 = try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload2)

        // Alice retrieves her second share
        XCTAssertEqual(try exampleStore.retrieveShare(publicKey: alicePublicKey, receipt: aliceReceipt2), alicePayload2)
        
        // Alice retrieves both her shares identified only by her public key.
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 2)
        
        // Bob attempts to retrieve one of Alice's shares
        XCTAssertThrowsError(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: aliceReceipt1))
        
        // Someone attempts to retrieve all shares from a nonexistent account
        XCTAssertThrowsError(try exampleStore.retrieveShares(publicKey: PrivateKeyBase().publicKeys))
        
        // Alice stores a share she's previously stored (idempotent)
        XCTAssertEqual(try exampleStore.storeShare(publicKey: alicePublicKey, payload: alicePayload1), aliceReceipt1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 2)
        
        // Alice deletes one of her shares
        try exampleStore.deleteShare(publicKey: alicePublicKey, receipt: aliceReceipt1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).count, 1)
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey).first!.1, alicePayload2)
        
        // Alice attempts to delete a share she already deleted (idempotent).
        XCTAssertNoThrow(try exampleStore.deleteShare(publicKey: alicePublicKey, receipt: aliceReceipt1))

        // Bob adds a fallback contact method
        try exampleStore.updateFallback(publicKey: bobPublicKey, fallback: "bob@example.com")
        XCTAssertEqual(try exampleStore.retrieveFallback(publicKey: bobPublicKey), "bob@example.com")
        
        // Alice has never set her fallback contact method
        XCTAssertNil(try exampleStore.retrieveFallback(publicKey: alicePublicKey))
        
        // Someone attempts to retrieve the fallback for a nonexistent account
        XCTAssertThrowsError(try exampleStore.retrieveFallback(publicKey: PrivateKeyBase().publicKeys))
        
        // Alice updates her public key to a new one
        let alicePublicKey2 = PrivateKeyBase().publicKeys
        try exampleStore.updatePublicKey(old: alicePublicKey, new: alicePublicKey2)

        // Alice can no longer retrieve her shares using the old public key
        XCTAssertThrowsError(try exampleStore.retrieveShares(publicKey: alicePublicKey))

        // Alice must now use her new public key
        XCTAssertEqual(try exampleStore.retrieveShares(publicKey: alicePublicKey2).count, 1)
        
        // Bob deletes his entire account
        exampleStore.deleteAccount(publicKey: bobPublicKey)

        // Attempting to retrieve his share now throws an error
        XCTAssertThrowsError(try exampleStore.retrieveShare(publicKey: bobPublicKey, receipt: bobReceipt1))

        // Attempting to retrieve his fallback now throws an error
        XCTAssertThrowsError(try exampleStore.retrieveFallback(publicKey: bobPublicKey))
    }
}

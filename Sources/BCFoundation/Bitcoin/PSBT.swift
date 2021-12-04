//
//  PSBT.swift
//  PSBT
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
@_exported import BCWally
@_exported import URKit

public struct PSBT : Equatable {
    public let inputs: [PSBTInput]
    public let outputs: [PSBTOutput]

    private var storage: Storage

    private final class Storage {
        var psbt: WallyPSBT

        init(psbt: WallyPSBT) {
            self.psbt = psbt
        }

        deinit {
            Wally.free(psbt: psbt)
        }
    }

    private var _psbt: WallyPSBT {
        storage.psbt
    }

    private static func clone(psbt: WallyPSBT) -> WallyPSBT {
        Wally.clone(psbt: psbt)
    }

    private mutating func prepareForWrite() {
        if !isKnownUniquelyReferenced(&storage) {
            storage.psbt = Self.clone(psbt: storage.psbt)
        }
    }

    public static func == (lhs: PSBT, rhs: PSBT) -> Bool {
        lhs.data == rhs.data
    }

    private init(ownedPSBT: WallyPSBT) {
        self.storage = Storage(psbt: ownedPSBT)

        var inputs: [PSBTInput] = []
        for i in 0 ..< ownedPSBT.pointee.inputs_allocation_len {
            inputs.append(PSBTInput(wallyInput: ownedPSBT.pointee.inputs![i]))
        }
        self.inputs = inputs

        var outputs: [PSBTOutput] = []
        for i in 0 ..< ownedPSBT.pointee.outputs_allocation_len {
            outputs.append(PSBTOutput(wallyPSBTOutput: ownedPSBT.pointee.outputs[i], wallyTxOutput: ownedPSBT.pointee.tx!.pointee.outputs[i]))
        }
        self.outputs = outputs
    }

    public init?(_ data: Data) {
        guard let psbt = Wally.psbt(from: data) else {
            return nil
        }
        precondition(psbt.pointee.tx != nil)
        self.init(ownedPSBT: psbt)
    }

    public init?(base64 string: String) {
        guard string.count != 0 else {
            return nil
        }

        guard let psbtData = Data(base64Encoded: string) else {
            return nil
        }

        self.init(psbtData)
    }

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var data: Data {
        return Wally.serialized(psbt: _psbt)
    }
    
    public var base64: String {
        data.base64EncodedString()
    }
    
    public var hex: String {
        data.hex
    }

    public var isFinalized: Bool {
        Wally.isFinalized(psbt: _psbt)
    }

    public var transaction: Transaction {
        precondition(_psbt.pointee.tx != nil)
        return Transaction(tx: _psbt.pointee.tx!)
    }
    
    public var totalIn: Satoshi? {
        let result = inputs.reduce(into: Satoshi(0)) { (total, input) in
            guard input.isSegwit, let amount = input.amount else {
                return
            }
            total += amount
        }
        return result
    }
    
    public var totalOut: Satoshi? {
        self.transaction.totalOut
    }

    public var fee: Satoshi? {
        guard
            let valueOut = totalOut,
            let valueIn = totalIn,
            valueIn >= valueOut
        else {
            return nil
        }
        return valueIn - valueOut
    }
    
    public var totalChange: Satoshi? {
        outputs.reduce(into: Satoshi(0)) { (total, output) in
            if output.isChange {
                total += output.amount
            }
        }
    }
    
    public var totalSent: Satoshi? {
        outputs.reduce(into: Satoshi(0)) { (total, output) in
            if !output.isChange {
                total += output.amount
            }
        }
    }

    public func finalizedTransaction() -> Transaction? {
        Wally.finalizedTransaction(psbt: _psbt)
    }

    public func signed(with privKey: ECPrivateKey) -> PSBT? {
        guard let signedPSBT = Wally.signed(psbt: _psbt, ecPrivateKey: privKey.data) else {
            return nil
        }
        return PSBT(ownedPSBT: signedPSBT)
    }

    public func signed(with hdKey: HDKey) -> PSBT? {
        var psbt = self
        for input in self.inputs {
            for origin in input.signableOrigins(with: hdKey) {
                if
                    let childKey = try? HDKey(parent: hdKey, childDerivationPath: origin.path),
                    let privKey = childKey.ecPrivateKey,
                    privKey.public == origin.key,
                    let signedPSBT = psbt.signed(with: privKey)
                {
                    psbt = signedPSBT
                }
            }
        }
        guard self != psbt else {
            return nil
        }
        return psbt
    }
    
    public func signed<SignerType: PSBTSigner>(with signer: SignerType) -> PSBT? {
        signed(with: signer.masterKey)
    }
    
    public func signed<SignerType: PSBTSigner>(with inputSigning: [PSBTInputSigning<SignerType>]) -> PSBT? {
        var signedPSBT = self
        for info in inputSigning {
            for signingStatus in info.statuses {
                if
                    !signingStatus.isSigned,
                    let signer = signingStatus.knownSigner
                {
                    if let psbt = signedPSBT.signed(with: signer) {
                        signedPSBT = psbt
                    }
                }
            }
        }
        return signedPSBT
    }

    public func finalized() -> PSBT? {
        guard let psbt = Wally.finalized(psbt: _psbt) else {
            return nil
        }
        return PSBT(ownedPSBT: psbt)
    }
    
    public var isFullySigned: Bool {
        inputs.allSatisfy { $0.isFullySigned }
    }
}

extension PSBT: CustomStringConvertible {
    public var description: String {
        base64
    }
}

public struct PSBTInputSigning<SignerType: PSBTSigner>: Identifiable {
    public let id: UUID = UUID()
    public let input: PSBTInput
    public let statuses: [PSBTSigningStatus<SignerType>]
}

public struct PSBTOutputSigning<SignerType: PSBTSigner>: Identifiable {
    public let id: UUID = UUID()
    public let output: PSBTOutput
    public let statuses: [PSBTSigningStatus<SignerType>]
}

extension PSBT {
    public func inputSigning<SignerType: PSBTSigner>(signers: [SignerType]) -> [PSBTInputSigning<SignerType>] {
        inputs.map { PSBTInputSigning(input: $0, statuses: $0.signingStatus(signers: signers)) }
    }
    
    public func outputSigning<SignerType: PSBTSigner>(signers: [SignerType]) -> [PSBTOutputSigning<SignerType>] {
        outputs.map { PSBTOutputSigning(output: $0, statuses: $0.signingStatus(signers: signers)) }
    }
    
    public static func countOfSignableInputs<SignerType: PSBTSigner>(for signings: [PSBTInputSigning<SignerType>]) -> Int {
        signings.reduce(into: 0) { total, signing in
            if signing.statuses.contains(where: { $0.canBeSigned }) {
                total += 1
            }
        }
    }
    
    public static func countOfUniqueSigners<SignerType: PSBTSigner>(for signings: [PSBTInputSigning<SignerType>]) -> Int {
        signings.reduce(into: Set<SignerType>()) { signers, signing in
            signing.statuses.forEach { status in
                if status.canBeSigned {
                    signers.insert(status.knownSigner!)
                }
            }
        }.count
    }
}

extension PSBT {
    public enum Error: Swift.Error {
        case unexpectedURType
        case invalidFormat
    }
    
    public init(ur: UR) throws {
        guard ur.type == "crypto-psbt" else {
            throw Error.unexpectedURType
        }
        guard let cbor = try CBOR.decode(ur.cbor.bytes) else {
            throw Error.invalidFormat
        }
        try self.init(cbor: cbor)
    }
    
    public init(urString: String) throws {
        try self.init(ur: URDecoder.decode(urString))
    }
    
    public init(parse string: String) throws {
        if let a = PSBT(base64: string) {
            self = a
            return
        }
        
        if let a = PSBT(hex: string) {
            self = a
            return
        }

        do {
            try self.init(urString: string)
        } catch { }

        throw Error.invalidFormat
    }
    
    public var ur: UR {
        try! UR(type: "crypto-psbt", cbor: cbor)
    }
    
    public var urString: String {
        ur.string
    }
    
    public var cbor: CBOR {
        CBOR.byteString(data.bytes)
    }

    public var taggedCBOR: CBOR {
        return CBOR.tagged(.psbt, cbor)
    }
    
    public init(cbor: CBOR) throws {
        guard
            case let CBOR.byteString(bytes) = cbor
        else {
            throw Error.invalidFormat
        }
        let data = Data(bytes)
        guard let psbt = PSBT(data) else {
            throw Error.invalidFormat
        }
        self = psbt
    }
    
    public init(taggedCBOR: CBOR) throws {
        guard case let CBOR.tagged(.psbt, cbor) = taggedCBOR else {
            throw Error.invalidFormat
        }
        try self.init(cbor: cbor)
    }
}

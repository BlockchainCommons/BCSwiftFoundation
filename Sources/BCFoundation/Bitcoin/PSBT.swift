//
//  PSBT.swift
//  PSBT
//
//  Originally create by Sjors. Heavily modified by Wolf McNally, Blockchain Commons Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import URKit

public struct PSBT : Equatable {
    public let inputs: [PSBTInput]
    public let outputs: [PSBTOutput]

    private var storage: Storage

    private final class Storage {
        var psbt: WallyPSBT

        init(psbt: WallyPSBT) { self.psbt = psbt }

        deinit { psbt.dispose() }
    }

    private var _psbt: WallyPSBT {
        storage.psbt
    }

    private mutating func prepareForWrite() {
        if !isKnownUniquelyReferenced(&storage) {
            storage.psbt = storage.psbt.clone()
        }
    }

    public static func == (lhs: PSBT, rhs: PSBT) -> Bool {
        lhs.data == rhs.data
    }

    private init(ownedPSBT: WallyPSBT) {
        self.storage = Storage(psbt: ownedPSBT)

        var inputs: [PSBTInput] = []
        for i in 0 ..< ownedPSBT.inputsAllocationCount {
            inputs.append(PSBTInput(wallyInput: ownedPSBT.input(at: i)))
        }
        self.inputs = inputs

        var outputs: [PSBTOutput] = []
        for i in 0 ..< ownedPSBT.outputsAllocationCount {
            outputs.append(PSBTOutput(wallyPSBTOutput: ownedPSBT.output(at: i), wallyTxOutput: ownedPSBT.tx.output(at: i)))
        }
        self.outputs = outputs
    }

    public init?(_ data: Data) {
        guard let psbt = Wally.psbt(from: data) else {
            return nil
        }
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
        return Transaction(tx: _psbt.tx)
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
                    privKey.secp256k1PublicKey == origin.key,
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
        var result: [PSBTInputSigning<SignerType>] = []
        for input in inputs {
            let statuses = input.signingStatus(signers: signers)
            let inputSigning = PSBTInputSigning(input: input, statuses: statuses)
            result.append(inputSigning)
        }
        return result
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

extension PSBT: URCodable {
    public static var cborTags = [Tag.psbt, Tag.psbtV1]
    
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
            self = try PSBT(urString: string)
        } catch { }

        throw CBORError.invalidFormat
    }
    
    public var untaggedCBOR: CBOR {
        CBOR.bytes(data)
    }
    
    public init(untaggedCBOR: CBOR) throws {
        guard
            case let CBOR.bytes(bytes) = untaggedCBOR
        else {
            throw CBORError.invalidFormat
        }
        let data = bytes.data
        guard let psbt = PSBT(data) else {
            throw CBORError.invalidFormat
        }
        self = psbt
    }
}

extension PSBT: EnvelopeCodable {
    public var envelope: Envelope {
        Envelope(data)
            .addType(.PSBT)
    }
    
    public init(envelope: Envelope) throws {
        try envelope.checkType(.PSBT)
        if
            let subjectLeaf = envelope.leaf,
            case CBOR.tagged(.psbtV1, let item) = subjectLeaf
        {
            self = try Self.init(untaggedCBOR: item)
            return
        }
        
        let data = try envelope.extractSubject(Data.self)
        guard let psbt = Self.init(data) else {
            throw EnvelopeError.invalidFormat
        }
        self = psbt
    }
}

extension PSBT: TransactionResponseBody {
    public static var type = Envelope(.PSBT)
}

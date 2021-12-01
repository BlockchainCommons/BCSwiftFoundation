# BCSwiftFoundation

A collection of useful primitives for cryptocurrency wallets.

Opinionated Swift wrapper around [LibWally](https://github.com/ElementsProject/libwally-core).

Supports particular enhancements used by Blockchain Commons from our fork of libwally-core: [bc-libwally-core](https://github.com/blockchaincommons/bc-libwally-core), in the [bc-maintenance](https://github.com/BlockchainCommons/bc-libwally-core/tree/bc-maintenance) branch.

# Dependencies

Depends on [BCSwiftWally](https://github.com/BlockchainCommons/BCSwiftWally), which is a thin wrapper around LibWally that has a new build system for building a universal XCFramework for use with MacOSX, Mac Catalyst, iOS devices, and the iOS simulator across Intel and Apple Silicon (ARM).

# Building

Add to your project like any other Swift Package.

# Usage

Derive address from a seed:

```swift
import BCFoundation

let mnemonic = try! BIP39Mnemonic(words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
let masterKey = try! HDKey(seed: mnemonic.seedHex(passphrase: "bip39 passphrase"))
let path = try! BIP32Path(string: "m/44'/0'/0'")
_ = masterKey.fingerprint
let account = try! masterKey.derive(using: path)
_ = account.xpub
_ = account.address(type: .payToWitnessPubKeyHash)
```

Derive address from an xpub:

```swift
let account = try! HDKey(base58: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
let receivePath = try! BIP32Path(string: "0/0")
let key = try! account.derive(using: receivePath)
_ = key.address(type: .payToPubKeyHash) // 1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj
```

Parse an address:

```swift
let address = try! Address(string: "bc1q6zwjfmhdl4pvhvfpv8pchvtanlar8hrhqdyv0t")
_ = address.scriptPubKey // 0014d09d24eeedfd42cbb12161c38bb17d9ffa33dc77
_ = address.scriptPubKey.type // .payToWitnessPubKeyHash
```

Create and sign a transaction:

```swift
let txId = "400b52dab0a2bb5ce5fdf5405a965394b43a171828cd65d35ffe1eaa0a79a5c4"
let vout: UInt32 = 1
let amount: Satoshi = 10000
let witness = Witness(.payToWitnessPubKeyHash(key.pubKey))
let input = TxInput(Transaction(txId)!, vout, amount, nil, witness, scriptPubKey)!
transaction = Transaction([input], [TxOutput(destinationAddress.scriptPubKey, amount - 110)])
transaction.feeRate // Satoshi per byte
let accountPriv = HDKey("xpriv...")
let privKey = try! accountPriv.derive(BIP32Path("0/0")!)
transaction.sign([privKey])
transaction.description # transaction hex
```

# web3-chain-btc

Bitcoin blockchain implementation for the Web3 Wallet SDK.

## 0.1.0 Support Matrix

| Type | Derive | Sign (spend) | Notes |
|------|:------:|:------------:|------|
| P2PKH (Legacy, `1...` / `m,n`) | ✅ | ✅ | BIP-44 |
| P2SH-P2WPKH (Wrapped SegWit, `3...` / `2`) | ✅ | ✅ | BIP-49. Input requires `amount` + the P2SH `scriptPubKey`. Signer strictly verifies the P2SH hash matches `hash160(0x00 0x14 hash160(pubkey))` — multisig / arbitrary P2SH are rejected with a clear error. |
| P2WPKH (Native SegWit, `bc1q...` / `tb1q`) | ✅ | ✅ | BIP-84. Input requires `amount` (BIP-143). |
| P2WSH (`bc1q...` / `tb1q`) | ⚠️ address-only | ❌ | Requires a script, not a public key. Not exposed via `AccountDeriver`. |
| P2TR (Taproot, `bc1p...` / `tb1p`) | ⏳ 0.2.0 | ⏳ 0.2.0 | High-level entry points (`BtcAddressEncoder.encode(P2TR, ...)` / `AccountDeriver.getPathForBtcType(P2TR, ...)`) throw `UnsupportedOperationException` to prevent deriving unspendable addresses. Low-level `TaprootAddress.fromPublicKey(...)` remains for parsing / experimentation. |

Encoding utilities (Base58Check, Bech32, Bech32m) are independent of the support matrix and continue to work for all types.

## Address generation

```java
import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

byte[] privateKey = new byte[32]; // Your 32-byte private key

try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
    byte[] pubKey = signer.getCompressedPublicKey();

    // Legacy P2PKH (starts with '1')
    P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET);

    // Wrapped SegWit P2SH-P2WPKH (starts with '3')
    P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(pubKey, BtcNetwork.MAINNET);

    // Native SegWit P2WPKH (starts with 'bc1q')
    Bech32Address bech32 = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.MAINNET);

    // ⚠️ Taproot — 0.1.0 cannot sign P2TR inputs yet. Available only for parsing / experiment.
    //    Do NOT send real funds to a derived bc1p... address with 0.1.0; you will not be
    //    able to spend them. Wait for 0.2.0 (BIP-340 Schnorr + BIP-341 sighash).
}
```

## Parse / validate

```java
BtcAddress addr = BtcAddress.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
System.out.println(addr.getType());     // P2WPKH
System.out.println(addr.getNetwork());  // MAINNET

boolean ok = BtcAddress.isValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // true

BtcAddressType type = BtcAddressType.fromAddress("bc1p..."); // P2TR (parsing only)
BtcNetwork network  = BtcNetwork.fromAddress("tb1q...");     // TESTNET
```

## Build & sign a transaction

⚠️ **SegWit inputs require `amount` and `scriptPubKey`**. BIP-143 includes the spent UTXO amount in the signature hash; the simplified `addInput(prevTxHash, idx)` overload defaults `amount=0` and **will be rejected** by the SegWit signing path. Use the overload that takes the UTXO amount and scriptPubKey.

```java
import io.github.superedison.web3.chain.btc.BtcChainAdapter;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;

byte[] prevTxHash = /* 32-byte previous tx hash */;
byte[] prevScriptPubKey = /* the scriptPubKey of the UTXO being spent */;
long prevAmount = 100_000L;             // satoshis locked in the UTXO

BtcRawTransaction tx = BtcRawTransaction.builder()
        .version(2)
        .segwit(true)
        // 4-arg form carries the amount + scriptPubKey required for BIP-143.
        // For P2SH-P2WPKH inputs, prevScriptPubKey must be the P2SH form
        // (OP_HASH160 <20> OP_EQUAL); the signer auto-detects and writes the
        // 22-byte redeemScript into scriptSig.
        .addInput(prevTxHash, 0, prevAmount, prevScriptPubKey)
        .addOutput(50_000L, recipientScript)
        .addOutput(49_000L, changeScript)
        .lockTime(0)
        .build();

BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
try (Secp256k1Signer key = new Secp256k1Signer(privateKey)) {
    BtcSignedTransaction signed = adapter.sign(tx, key);
    String txHex = signed.encodeHex();
    String txid  = signed.txHashHex();
}
```

## Networks

```java
BtcChainAdapter mainnet = new BtcChainAdapter(BtcNetwork.MAINNET);
BtcChainAdapter testnet = new BtcChainAdapter(BtcNetwork.TESTNET);
```

## BIP coverage

| BIP | Topic | 0.1.0 status |
|-----|-------|:------------:|
| BIP-44  | HD account hierarchy (P2PKH) | ✅ |
| BIP-49  | SegWit-compatible derivation (P2SH-P2WPKH) | ✅ |
| BIP-84  | Native SegWit derivation (P2WPKH) | ✅ |
| BIP-86  | Taproot derivation (P2TR) | ⏳ 0.2.0 |
| BIP-141 | SegWit consensus rules | ✅ |
| BIP-143 | SegWit signature hash | ✅ |
| BIP-173 | Bech32 encoding | ✅ |
| BIP-340 | Schnorr signatures | ⏳ 0.2.0 |
| BIP-341 | Taproot sighash | ⏳ 0.2.0 |
| BIP-350 | Bech32m encoding | ✅ (parsing only) |

## Architecture

```
btc/
├── address/                       # Address types + encoding (Base58Check, Bech32, Bech32m)
├── tx/                            # Transaction model (BtcRawTransaction, BtcSignedTransaction)
├── internal/                      # BIP-143 encoder, txid hasher, ECDSA signer
└── BtcChainAdapter.java           # ChainAdapter SPI implementation
```

## Dependencies

- `web3-chain-spi` — Chain SPI contracts
- `web3-crypto` — Secp256k1 signing, SHA256, RIPEMD160

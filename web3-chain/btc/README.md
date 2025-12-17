# web3-chain-btc

Bitcoin blockchain implementation for the Web3 Wallet SDK.

## Features

- **Multiple Address Types**
  - P2PKH (Legacy, starts with `1`)
  - P2SH-P2WPKH (Wrapped SegWit, starts with `3`)
  - P2WPKH (Native SegWit, starts with `bc1q`)
  - P2WSH (Native SegWit Script, starts with `bc1q`)
  - P2TR (Taproot, starts with `bc1p`)

- **Network Support**
  - Mainnet
  - Testnet
  - Regtest

- **Encoding**
  - Base58Check (for P2PKH, P2SH)
  - Bech32 (for P2WPKH, P2WSH - BIP-173)
  - Bech32m (for Taproot - BIP-350)

- **Transaction**
  - Legacy and SegWit transaction formats
  - BIP-143 signature hash (for SegWit)

## Address Types

| Type | Class | Prefix (Mainnet) | Prefix (Testnet) | BIP |
|------|-------|------------------|------------------|-----|
| P2PKH | `P2PKHAddress` | `1` | `m`, `n` | BIP-44 |
| P2SH-P2WPKH | `P2SHAddress` | `3` | `2` | BIP-49 |
| P2WPKH | `Bech32Address` | `bc1q` | `tb1q` | BIP-84 |
| P2WSH | `Bech32Address` | `bc1q` | `tb1q` | BIP-84 |
| P2TR | `TaprootAddress` | `bc1p` | `tb1p` | BIP-86 |

## Usage

### Generate Addresses

```java
import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

byte[] privateKey = new byte[32]; // Your 32-byte private key

try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
    byte[] pubKey = signer.getCompressedPublicKey();

    // Legacy P2PKH (starts with '1')
    P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET);
    System.out.println("Legacy: " + p2pkh.toBase58());

    // Wrapped SegWit P2SH-P2WPKH (starts with '3')
    P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(pubKey, BtcNetwork.MAINNET);
    System.out.println("Wrapped SegWit: " + p2sh.toBase58());

    // Native SegWit P2WPKH (starts with 'bc1q')
    Bech32Address bech32 = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.MAINNET);
    System.out.println("Native SegWit: " + bech32.toBech32());

    // Taproot P2TR (starts with 'bc1p')
    TaprootAddress taproot = TaprootAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET);
    System.out.println("Taproot: " + taproot.toBech32m());
}
```

### Parse Address

```java
// Parse any Bitcoin address
BtcAddress addr = BtcAddress.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

System.out.println("Type: " + addr.getType());       // P2WPKH
System.out.println("Network: " + addr.getNetwork()); // MAINNET
System.out.println("Hash: " + bytesToHex(addr.getHash()));

// Type-specific parsing
P2PKHAddress legacy = P2PKHAddress.fromBase58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
Bech32Address segwit = Bech32Address.fromBech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
TaprootAddress taproot = TaprootAddress.fromBech32("bc1p...");
```

### Validate Address

```java
// Validate any address
boolean isValid = BtcAddress.isValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // true

// Detect address type
BtcAddressType type = BtcAddressType.fromAddress("bc1p...");  // P2TR

// Detect network
BtcNetwork network = BtcNetwork.fromAddress("tb1q...");  // TESTNET
```

### Get ScriptPubKey

```java
// Get scriptPubKey for each address type
byte[] p2pkhScript = p2pkh.getScriptPubKey();     // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
byte[] p2shScript = p2sh.getScriptPubKey();       // OP_HASH160 <20> OP_EQUAL
byte[] bech32Script = bech32.getScriptPubKey();   // OP_0 <20>
byte[] taprootScript = taproot.getScriptPubKey(); // OP_1 <32>
```

### Build & Sign Transaction

```java
import io.github.superedison.web3.chain.btc.BtcChainAdapter;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;

// Build transaction
byte[] prevTxHash = /* previous tx hash (32 bytes) */ new byte[32];
byte[] recipientScript = /* recipient's scriptPubKey */ new byte[25];

BtcRawTransaction tx = BtcRawTransaction.builder()
        .version(2)
        .addInput(prevTxHash, 0)            // UTXO: txid, output index
        .addOutput(50000L, recipientScript) // 50000 satoshis to recipient
        .addOutput(49000L, changeScript)    // Change output
        .lockTime(0)
        .segwit(true)                       // SegWit transaction
        .build();

// Sign
BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);

try (Secp256k1Signer key = new Secp256k1Signer(privateKey)) {
    BtcSignedTransaction signed = adapter.sign(tx, key);

    String txHex = signed.encodeHex();     // Raw transaction hex
    String txid = signed.txHashHex();      // Transaction ID
    byte[] rawBytes = signed.rawBytes();   // Raw bytes for broadcast
}
```

## Testnet Usage

```java
// Generate testnet addresses
P2PKHAddress testnetLegacy = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.TESTNET);
// Output: mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef (starts with 'm' or 'n')

Bech32Address testnetSegwit = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.TESTNET);
// Output: tb1q... (starts with 'tb1q')

TaprootAddress testnetTaproot = TaprootAddress.fromPublicKey(pubKey, BtcNetwork.TESTNET);
// Output: tb1p... (starts with 'tb1p')

// Use testnet adapter
BtcChainAdapter testnetAdapter = new BtcChainAdapter(BtcNetwork.TESTNET);
```

## BIP Standards

| BIP | Description | Address Type |
|-----|-------------|--------------|
| BIP-44 | Multi-account HD (m/44'/0'/0'/0/0) | P2PKH |
| BIP-49 | SegWit-compatible (m/49'/0'/0'/0/0) | P2SH-P2WPKH |
| BIP-84 | Native SegWit (m/84'/0'/0'/0/0) | P2WPKH |
| BIP-86 | Taproot (m/86'/0'/0'/0/0) | P2TR |
| BIP-141 | SegWit consensus rules | SegWit transactions |
| BIP-143 | SegWit signature hash | SegWit signing |
| BIP-173 | Bech32 encoding | P2WPKH, P2WSH |
| BIP-350 | Bech32m encoding | Taproot |

## Architecture

```
btc/
├── address/
│   ├── BtcAddress.java         # Unified address interface (sealed)
│   ├── BtcAddressType.java     # Address type enum
│   ├── BtcNetwork.java         # Network enum (mainnet/testnet/regtest)
│   ├── P2PKHAddress.java       # Legacy addresses
│   ├── P2SHAddress.java        # Wrapped SegWit addresses
│   ├── Bech32Address.java      # Native SegWit addresses
│   ├── TaprootAddress.java     # Taproot addresses
│   ├── Base58Check.java        # Base58Check encoding
│   └── Bech32.java             # Bech32/Bech32m encoding
├── tx/
│   ├── BtcRawTransaction.java  # Raw transaction model
│   └── BtcSignedTransaction.java
├── internal/
│   ├── BtcTransactionEncoder.java
│   ├── BtcTransactionHasher.java
│   └── BtcTransactionSigner.java
└── BtcChainAdapter.java        # ChainAdapter implementation
```

## Dependencies

- `web3-chain-spi` - Chain SPI contracts
- `web3-crypto` - Secp256k1 signing, SHA256, RIPEMD160

## License

MIT licensed. Free to use in wallets, exchanges, SaaS and other commercial products.

# Web3 Wallet SDK (Java 21+)

Modular, security-first Web3 wallet SDK. Current focus: EVM + TRON, with an extensible chain SPI and crypto primitives.

## Modules

| Module | Description |
|--------|-------------|
| web3-core | Semantic/safety abstractions (RawTransaction, SignedTransaction, SigningKey, Address) |
| web3-crypto | Pure crypto (hash, Secp256k1/Ed25519, BIP-32/39/44, SecureBytes) |
| web3-chain | Chain abstractions (shared types) |
| web3-chain-spi | Chain SPI (ChainAdapter, ChainType, encoder/hasher/signer contracts) |
| web3-chain-evm | EVM implementation (RLP encoding, Keccak hashing, secp256k1 signing) |
| web3-chain-tron | TRON implementation (Protobuf encoding, SHA256 txid, secp256k1 signing) |
| web3-client | Entry + adapter registry |

Dependency direction (one-way):
```
web3-client
  └─► web3-chain-evm / web3-chain-tron
          └─► web3-chain-spi ──► web3-core
                                └─► web3-crypto
```

## Quickstart (EVM)

```java
import io.github.superedison.web3.chain.evm.EvmChainAdapter;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.tx.EvmSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import java.math.BigInteger;

// 1) Build intent
EvmRawTransaction tx = EvmRawTransaction.builder()
        .nonce(1)
        .gasPrice(BigInteger.valueOf(20_000_000_000L))
        .gasLimit(21_000)
        .to("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE7")
        .value(BigInteger.valueOf(1_000_000_000_000_000_000L))
        .chainId(1)
        .build();

// 2) Pick adapter (or use ServiceLoader for auto-discovery)
ChainAdapter<EvmRawTransaction, EvmSignedTransaction> adapter = new EvmChainAdapter();

// 3) Sign with secp256k1 private key
byte[] privateKey = /* your 32-byte secp256k1 private key */ new byte[32];
try (Secp256k1Signer key = new Secp256k1Signer(privateKey)) {
    EvmSignedTransaction signed = adapter.sign(tx, key);
    byte[] rawBytes = adapter.rawBytes(signed); // broadcast bytes
    byte[] txHash   = adapter.txHash(signed);   // txHash
}
```

## Quickstart (TRON)

```java
import io.github.superedison.web3.chain.tron.TronChainAdapter;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

// Build intent (transfer)
TronRawTransaction tx = TronRawTransaction.builder()
        .from("T...")                  // sender (Base58)
        .to("T...")                    // recipient (Base58)
        .amount(1_000_000)             // sun
        .refBlockBytes(new byte[]{0x00, 0x01})
        .refBlockHash(new byte[8])
        .expiration(System.currentTimeMillis() + 600_000)
        .timestamp(System.currentTimeMillis())
        .feeLimit(10_000_000)
        .build();

ChainAdapter<TronRawTransaction, TronSignedTransaction> adapter = new TronChainAdapter();

try (Secp256k1Signer key = new Secp256k1Signer(/* 32-byte private key */ new byte[32])) {
    TronSignedTransaction signed = adapter.sign(tx, key);
    byte[] rawBytes = adapter.rawBytes(signed); // broadcast bytes
    byte[] txHash   = adapter.txHash(signed);   // txid (SHA256(raw_data))
}
```

## Chain extension (SPI)
- Interface: `io.github.superedison.web3.chain.spi.ChainAdapter`
- SPI file: `META-INF/services/io.github.superedison.web3.chain.spi.ChainAdapter`
- EVM example combines `TransactionEncoder` (RLP) + `TransactionHasher` (Keccak) + `TransactionSigner` (secp256k1).
- TRON example combines `TransactionEncoder` (Protobuf raw_data) + `TransactionHasher` (SHA256 raw_data) + `TransactionSigner` (secp256k1).

## Multi-chain plan

| Chain | Curve | Default path | Status |
|-------|-------|--------------|--------|
| EVM | secp256k1 | m/44'/60'/0'/0/0 | Ready |
| TRON | secp256k1 | m/44'/195'/0'/0/0 | Ready |
| Others | - | - | Planned |

To add a chain: implement `ChainAdapter`, your Raw/SignedTransaction, encoder/hasher/signer, then register via SPI.

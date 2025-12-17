# web3-chain-solana

Solana blockchain implementation for the Web3 Wallet SDK.

## Features

- **Address**
  - Ed25519 public key (32 bytes)
  - Base58 encoding (no checksum)
  - Address validation

- **Transaction**
  - Message-based transaction format
  - Ed25519 signature (64 bytes)
  - Multi-signature support
  - Recent blockhash for transaction expiry

- **Signing**
  - Ed25519 signing algorithm
  - Transaction hash = first signature

## Usage

### Generate Address

```java
import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;

byte[] privateKey = new byte[32]; // Your 32-byte private key

try (Ed25519Signer signer = new Ed25519Signer(privateKey)) {
    byte[] publicKey = signer.getPublicKey();

    // Create address from public key
    SolanaAddress address = SolanaAddress.fromPublicKey(publicKey);
    System.out.println("Address: " + address.toBase58());
    // Output: Base58 encoded address (e.g., "4fYNw3dojWmQ4dXtSGE9epjRGy9pFSx62YypT7avPYvA")
}
```

### Parse Address

```java
// Parse from Base58 string
SolanaAddress address = SolanaAddress.fromBase58("4fYNw3dojWmQ4dXtSGE9epjRGy9pFSx62YypT7avPYvA");

System.out.println("Base58: " + address.toBase58());
System.out.println("Hex: " + address.toHex());
System.out.println("Bytes: " + address.toBytes().length); // 32
```

### Validate Address

```java
// Validate address format
boolean isValid = SolanaAddress.isValid("4fYNw3dojWmQ4dXtSGE9epjRGy9pFSx62YypT7avPYvA"); // true
boolean invalid = SolanaAddress.isValid("invalid"); // false
```

### Build & Sign Transaction

```java
import io.github.superedison.web3.chain.solana.SolanaChainAdapter;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaSignedTransaction;

// System Program ID (all zeros for native transfer)
byte[] SYSTEM_PROGRAM = new byte[32];

try (Ed25519Signer signer = new Ed25519Signer(privateKey)) {
    byte[] publicKey = signer.getPublicKey();

    // Build transaction
    SolanaRawTransaction tx = SolanaRawTransaction.builder()
            .recentBlockhash("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N") // Base58 blockhash
            .feePayer(publicKey)
            .addAccount(publicKey, true, true)     // Signer, writable
            .addAccount(recipientPubkey, false, true) // Recipient, writable
            .addInstruction(SYSTEM_PROGRAM, List.of(0, 1), transferData)
            .build();

    // Sign transaction
    SolanaChainAdapter adapter = new SolanaChainAdapter();
    SolanaSignedTransaction signedTx = adapter.sign(tx, signer);

    // Get transaction details
    String base64 = signedTx.encodeBase64();      // For RPC submission
    String signature = signedTx.signatureBase58(); // Transaction signature
    byte[] rawBytes = signedTx.rawBytes();        // Raw bytes
    byte[] txHash = signedTx.txHash();            // Transaction hash (= signature)
}
```

### Using Blockhash as Bytes

```java
// You can also use raw bytes for blockhash
byte[] recentBlockhash = fetchRecentBlockhash(); // 32 bytes from RPC

SolanaRawTransaction tx = SolanaRawTransaction.builder()
        .recentBlockhash(recentBlockhash) // byte[] version
        .feePayer(publicKey)
        // ... rest of transaction
        .build();
```

## Transaction Structure

Solana transactions consist of:

1. **Signatures** - Ed25519 signatures (64 bytes each)
2. **Message Header** - Number of signers, read-only accounts
3. **Account Addresses** - Array of 32-byte public keys
4. **Recent Blockhash** - 32 bytes for transaction expiry (~60 seconds)
5. **Instructions** - Program calls with account indices and data

```
Transaction Layout:
┌─────────────────────────────────────────┐
│ Compact Array: Signatures               │
├─────────────────────────────────────────┤
│ Message:                                │
│   ├── Header (3 bytes)                  │
│   ├── Compact Array: Account Keys       │
│   ├── Recent Blockhash (32 bytes)       │
│   └── Compact Array: Instructions       │
└─────────────────────────────────────────┘
```

## Account Meta

Each account in a transaction has metadata:

| Property | Description |
|----------|-------------|
| `pubkey` | 32-byte Ed25519 public key |
| `isSigner` | Whether this account must sign |
| `isWritable` | Whether this account can be modified |

```java
// Add accounts with different permissions
builder.addAccount(feePayer, true, true);    // Signer + Writable
builder.addAccount(recipient, false, true);   // Writable only
builder.addAccount(programId, false, false);  // Read-only
```

## Instruction Format

Instructions specify program calls:

```java
// Create instruction
builder.addInstruction(
    programId,         // 32-byte program address
    List.of(0, 1),     // Indices into account array
    instructionData    // Program-specific data
);
```

## Common Program IDs

| Program | ID (Base58) |
|---------|-------------|
| System Program | `11111111111111111111111111111111` |
| Token Program | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| Associated Token | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` |

## Architecture

```
solana/
├── address/
│   ├── Base58.java           # Base58 encoding (no checksum)
│   └── SolanaAddress.java    # 32-byte Ed25519 address
├── tx/
│   ├── SolanaRawTransaction.java    # Transaction builder
│   └── SolanaSignedTransaction.java # Signed transaction
├── internal/
│   ├── SolanaTransactionEncoder.java # Message serialization
│   ├── SolanaTransactionHasher.java  # Hash = signature
│   └── SolanaTransactionSigner.java  # Ed25519 signing
└── SolanaChainAdapter.java   # ChainAdapter implementation
```

## Dependencies

- `web3-chain-spi` - Chain SPI contracts
- `web3-crypto` - Ed25519 signing

## Key Differences from Other Chains

| Feature | Solana | Bitcoin | Ethereum |
|---------|--------|---------|----------|
| Address | Ed25519 pubkey | Hash160 | Keccak256 |
| Encoding | Base58 | Base58Check/Bech32 | Hex |
| Signature | Ed25519 | ECDSA secp256k1 | ECDSA secp256k1 |
| Tx Hash | First signature | Double SHA256 | Keccak256 |
| Fee | Per signature | Per byte | Gas |

## Error Handling

```java
try {
    SolanaAddress address = SolanaAddress.fromBase58("invalid");
} catch (AddressException e) {
    // Invalid Base58 or wrong length
    System.err.println(e.getMessage());
}

try {
    SolanaRawTransaction tx = SolanaRawTransaction.builder()
            .feePayer(publicKey)
            .build(); // Missing recentBlockhash
} catch (IllegalStateException e) {
    // Recent blockhash is required
}
```

## Notes

- Solana addresses are case-sensitive (Base58)
- Transactions expire after ~60 seconds (based on recent blockhash)
- Transaction hash is the Base58-encoded first signature
- All accounts must be declared upfront in the transaction
- Ed25519Signer is required (Secp256k1Signer will throw error)

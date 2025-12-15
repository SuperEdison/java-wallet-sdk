# web3-crypto

加密原语与 HD 派生。

## 功能

| 类别 | 类 | 说明 |
|------|-----|------|
| 哈希 | `Keccak256`、`Sha256`、`Blake2b` | 常用哈希算法 |
| 签名 | `Secp256k1Signer`、`Ed25519Signer` | 实现 SigningKey 接口 |
| 助记词 | `Bip39` | 生成/验证助记词，转种子 |
| HD 派生 | `Bip32`、`Bip44` | secp256k1 密钥派生 |
| HD 派生 | `Slip10` | Ed25519 密钥派生（Solana/NEAR/Aptos） |
| 工具 | `SecureBytes` | 安全擦除/拷贝/常量时间比较 |

## BIP-32 (secp256k1)

```java
byte[] seed = Bip39.mnemonicToSeed(mnemonic, "");
try (Bip32.ExtendedKey key = Bip32.derivePath(seed, "m/44'/60'/0'/0/0")) {
    byte[] privateKey = key.privateKey();
    byte[] publicKey = key.getUncompressedPublicKey();
}
```

## SLIP-0010 (Ed25519)

```java
byte[] seed = Bip39.mnemonicToSeed(mnemonic, "");
try (Slip10.ExtendedKey master = Slip10.masterKeyFromSeed(seed, Slip10.Curve.ED25519)) {
    try (Slip10.ExtendedKey key = Slip10.derivePath(master, "m/44'/501'/0'/0'")) {
        byte[] ed25519Seed = key.getKey();  // 32 字节
    }
}
```

## 签名器

```java
// Secp256k1 (ETH/BTC)
try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
    Signature sig = signer.sign(hash32);
    System.out.println(signer);  // "Secp256k1Signer{***REDACTED***}"
}

// Ed25519 (Solana/NEAR)
try (Ed25519Signer signer = new Ed25519Signer(seed32)) {
    Signature sig = signer.sign(message);
}
```

## SecureBytes

```java
SecureBytes.secureWipe(sensitiveData);      // 安全擦除
byte[] copy = SecureBytes.copy(data);       // 安全复制
byte[] random = SecureBytes.randomBytes(32);// 安全随机
boolean eq = SecureBytes.constantTimeEquals(a, b); // 常量时间比较
```

## 安全特性

- `Bip32.ExtendedKey` / `Slip10.ExtendedKey` 实现 `AutoCloseable`
- `Secp256k1Signer` / `Ed25519Signer` 的 `toString()` 返回打码内容
- 销毁后调用方法抛出 `IllegalStateException`

# web3-core

通用接口层，不含链或加密实现。

## 主要接口

| 包 | 接口 | 说明 |
|----|------|------|
| `wallet` | `Wallet`、`HDWallet`、`KeyHolder`、`Address` | 钱包抽象 |
| `signer` | `SigningKey`、`Signer`、`Signature`、`SignatureScheme` | 签名抽象 |
| `transaction` | `RawTransaction`、`SignedTransaction`、`TransactionType` | 交易抽象 |
| `exception` | `Web3Exception`、`WalletException`、`SigningException` | 异常体系 |

## SigningKey（核心）

私钥是"能力"，不是"数据"：

```java
public interface SigningKey extends AutoCloseable {
    Signature sign(byte[] hash);     // 签名
    byte[] getPublicKey();           // 公钥
    SignatureScheme getScheme();     // 算法
    void destroy();                  // 销毁
    boolean isDestroyed();
    // 没有 getPrivateKey()！
}
```

## SignatureScheme

```java
public enum SignatureScheme {
    ECDSA_SECP256K1,   // ETH, BTC
    ED25519,           // SOL, NEAR, APTOS
    SCHNORR_SECP256K1, // BTC Taproot
    SR25519            // Polkadot
}
```

链相关接口（ChainAdapter/ChainType/ChainConfig）位于 `web3-chain` 模块。

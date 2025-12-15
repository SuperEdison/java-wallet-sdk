# web3-chain

链抽象层。

## 接口

| 接口 | 说明 |
|------|------|
| `ChainAdapter` | 链适配器 SPI（地址/钱包/交易/签名） |
| `ChainType` | 已支持/规划链列表，含曲线类型和默认 HD 路径 |

## ChainType

```java
public enum ChainType {
    EVM("secp256k1", "m/44'/60'/0'/0/0"),
    BTC("secp256k1", "m/84'/0'/0'/0/0"),
    SOL("ed25519", "m/44'/501'/0'/0'"),
    APTOS("ed25519", "m/44'/637'/0'/0'/0'"),
    TRON("secp256k1", "m/44'/195'/0'/0/0"),
    COSMOS("secp256k1", "m/44'/118'/0'/0/0"),
    NEAR("ed25519", "m/44'/397'/0'");

    public String getCurve();       // "secp256k1" 或 "ed25519"
    public String getDefaultPath(); // 默认 HD 路径
    public boolean isSecp256k1();
    public boolean isEd25519();
}
```

## ChainAdapter

```java
public interface ChainAdapter {
    ChainType getChainType();
    ChainConfig getChainConfig();

    // 地址
    boolean isValidAddress(String address);
    Address parseAddress(String address);
    Address deriveAddress(byte[] publicKey);

    // 钱包
    HDWallet createHDWallet(int wordCount);
    HDWallet fromMnemonic(List<String> mnemonic, String passphrase, String path);
    Wallet fromPrivateKey(byte[] privateKey);

    // 交易
    byte[] encodeTransaction(RawTransaction tx);
    byte[] hashTransaction(RawTransaction tx);
    byte[] encodeSignedTransaction(SignedTransaction tx);

    // 消息
    byte[] hashMessage(byte[] message);

    // 签名恢复
    Address recoverSigner(byte[] hash, Signature signature);
}
```

## 新增链

1. 实现 `ChainAdapter` 接口
2. 通过 SPI 注册：`META-INF/services/io.github.superedison.web3.chain.ChainAdapter`

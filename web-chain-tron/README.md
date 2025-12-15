# web-chain-tron

TRON (波场) 链适配器实现。

## 功能

| 功能 | 类 | 说明 |
|------|-----|------|
| 地址 | `TronAddress`、`Base58Check` | Base58Check 格式 (T开头) |
| 交易 | `TronRawTransaction`、`TronSignedTransaction` | TRX/TRC-20 转账 |
| 签名 | `TronTransactionSigner`、`TronMessageSigner` | 交易/消息签名 |
| 钱包 | `TronHDWallet`、`TronWallet`、`TronSigner` | BIP-32/44 HD 钱包 |
| Protobuf | `TronProtobuf` | 交易编码 |
| 适配器 | `TronChainAdapter` | ChainAdapter 实现 |

## 使用

```java
// 1. 创建 HD 钱包
TronChainAdapter adapter = new TronChainAdapter();
HDWallet wallet = adapter.createHDWallet(24);  // 默认 m/44'/195'/0'/0/0
String addr = wallet.getAddress().toBase58();  // T开头的地址

// 2. 从助记词恢复
HDWallet restored = adapter.fromMnemonic(
    List.of("abandon", "abandon", ...),
    "",
    null  // 使用默认路径
);

// 3. 从私钥创建
Wallet simple = adapter.fromPrivateKey(privateKeyBytes);

// 4. 构造 TRX 转账交易
TronRawTransaction tx = TronRawTransaction.builder()
    .type(TronTransactionType.TRANSFER_CONTRACT)
    .from("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb")
    .to("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW")
    .amount(1_000_000)  // 1 TRX = 1_000_000 sun
    .refBlockBytes(refBlockBytes)
    .refBlockHash(refBlockHash)
    .expiration(System.currentTimeMillis() + 60_000)
    .timestamp(System.currentTimeMillis())
    .build();

// 5. 签名
TronSignedTransaction signed = TronTransactionSigner.sign(tx, privateKey);
byte[] rawTx = signed.encode();
String txHash = signed.getTransactionHashHex();
```

## TRC-20 转账

```java
// TRC-20 transfer(address,uint256) 调用
String data = "a9059cbb" +  // 函数选择器
    "000000000000000000000000" + toAddressHex +  // 目标地址 (去掉41前缀)
    "0000000000000000000000000000000000000000000000000000000000000001";  // 金额

TronRawTransaction tx = TronRawTransaction.builder()
    .type(TronTransactionType.TRIGGER_SMART_CONTRACT)
    .from(fromAddress)
    .to(contractAddress)  // TRC-20 合约地址
    .amount(0)
    .data(data)
    .feeLimit(10_000_000)  // 10 TRX 费用上限
    .refBlockBytes(refBlockBytes)
    .refBlockHash(refBlockHash)
    .expiration(System.currentTimeMillis() + 60_000)
    .timestamp(System.currentTimeMillis())
    .build();

TronSignedTransaction signed = TronTransactionSigner.sign(tx, privateKey);
```

## 消息签名

```java
// 签名消息
Signature sig = TronMessageSigner.signMessage("Hello TRON", privateKey);

// 验证消息
boolean valid = TronMessageSigner.verifyMessage("Hello TRON", sig, publicKey);

// 恢复签名者地址
byte[] hash = TronMessageSigner.hashMessage("Hello TRON");
Address signer = adapter.recoverSigner(hash, sig);
```

## 技术规格

| 项目 | 值 |
|------|-----|
| 曲线 | secp256k1 |
| 地址长度 | 21 字节 (0x41 + 20字节) |
| 地址编码 | Base58Check |
| 交易编码 | Protocol Buffer |
| HD 路径 | m/44'/195'/0'/0/0 |
| 单位 | 1 TRX = 1,000,000 sun |
| 消息前缀 | `\x19TRON Signed Message:\n` |

## 支持的交易类型

| 类型 | 枚举值 | 说明 |
|------|--------|------|
| TRX 转账 | `TRANSFER_CONTRACT` | 原生 TRX 转账 |
| 合约调用 | `TRIGGER_SMART_CONTRACT` | TRC-20 等合约调用 |

## 地址格式

TRON 地址支持两种格式：

1. **Base58Check** (推荐): `T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb`
2. **十六进制**: `41a614f803b6fd780986a42c78ec9c7f77e6ded13c`

```java
TronAddress address = TronAddress.fromBase58("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");
String hex = address.toHex();      // 41a614f803b6fd780986a42c78ec9c7f77e6ded13c
String base58 = address.toBase58(); // T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb
```

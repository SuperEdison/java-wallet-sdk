# web3-chain-evm

EVM 链适配器实现。

## 功能

| 功能 | 类 | 说明 |
|------|-----|------|
| 地址 | `EvmAddress`、`Eip55Checksum` | EIP-55 校验格式 |
| 交易 | `EvmRawTransaction`、`EvmSignedTransaction` | Legacy/EIP-155 |
| 签名 | `EvmTransactionSigner`、`EvmMessageSigner` | 交易/EIP-191 消息 |
| 钱包 | `EvmHDWallet`、`EvmWallet`、`EvmSigner` | BIP-32/44 HD 钱包 |
| RLP | `RlpEncoder` | 交易编码 |
| 适配器 | `EvmChainAdapter` | ChainAdapter 实现 |

## 使用

```java
// 1. 创建 HD 钱包
EvmChainAdapter adapter = new EvmChainAdapter();
HDWallet wallet = adapter.createHDWallet(24);  // 默认 m/44'/60'/0'/0/0
String addr = wallet.getAddress().toString();

// 2. 构造交易
EvmRawTransaction tx = EvmRawTransaction.builder()
    .nonce(1)
    .gasPrice(BigInteger.valueOf(20_000_000_000L))
    .gasLimit(21_000)
    .to("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE7")
    .value(BigInteger.TEN)
    .chainId(1)
    .build();

// 3. 签名
Signature sig = wallet.getSigner().sign(tx.hash());

// 4. 编码签名交易
EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, privateKey);
byte[] rawTx = signed.encode();
```

## 消息签名 (EIP-191)

```java
Signature sig = EvmMessageSigner.signMessage("Hello", privateKey);
boolean valid = EvmMessageSigner.verifyMessage("Hello", sig, publicKey);
```

## 支持标准

| EIP | 说明 | 状态 |
|-----|------|------|
| EIP-55 | 地址校验和 | ✅ |
| EIP-155 | 重放保护签名 | ✅ |
| EIP-191 | personal_sign | ✅ |
| EIP-712 | 类型化数据签名 | 🚧 |
| EIP-1559 | 费用市场交易 | 🚧 |

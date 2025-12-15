## License

MIT licensed.  
Free to use in wallets, exchanges, SaaS and other commercial products.

# Web3 Wallet SDK

Java 21+ 的模块化 Web3 钱包 SDK，安全优先，当前实现 EVM 链，提供可扩展的链适配接口与加密原语（BIP-32/39/44、SLIP-0010、Secp256k1、Ed25519）。

## 模块

| 模块 | 说明 |
|------|------|
| [`web3-core`](web3-core/README.md) | 钱包、签名、交易等通用接口 |
| [`web3-crypto`](web3-crypto/README.md) | 哈希/签名/BIP-32/39/44、SLIP-0010、SecureBytes |
| [`web3-chain`](web3-chain/README.md) | 链抽象层（ChainAdapter/ChainType） |
| [`web3-chain-evm`](web3-chain-evm/README.md) | EVM 适配器（地址/交易/消息签名/HD 钱包） |
| [`web-chain-tron`](web-chain-tron/README.md) | TRON 适配器（地址/交易/消息签名/HD 钱包） |
| [`web3-chain-btc`](web3-chain-btc/README.md) | 预留占位 |
| [`web3-abi`](web3-abi/README.md) | 预留占位 |
| [`web3-client`](web3-client/README.md) | 统一入口，适配器注册与账户派生工具 |

## 模块依赖

```
web3-client ──┬──▶ web3-chain-evm ──▶ web3-chain ──┬──▶ web3-core
              │                                    │
              └────────────────────────────────────┴──▶ web3-crypto
```

## 快速使用

```java
Web3Client client = Web3Client.builder().autoDiscover().build();

// 创建 HD 钱包（默认路径 m/44'/60'/0'/0/0）
HDWallet wallet = client.adapter(ChainType.EVM).createHDWallet(24);
String from = wallet.getAddress().toString();

// 构造交易
EvmRawTransaction tx = EvmRawTransaction.builder()
    .nonce(1)
    .gasPrice(BigInteger.valueOf(20_000_000_000L))
    .gasLimit(21_000)
    .to("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE7")
    .value(BigInteger.valueOf(1_000_000_000_000_000_000L))
    .chainId(1)
    .build();

// 签名
Signature sig = wallet.getSigner().sign(tx.hash());
```

## 安全要点

- `SigningKey`/`Signer` 不暴露私钥；`toString()` 返回 `{***REDACTED***}`
- `SecureBytes` 提供安全擦除与安全拷贝
- `Bip32.ExtendedKey` / `Slip10.ExtendedKey` 实现 `AutoCloseable`
- 钱包/签名器/KeyHolder 支持 `destroy()`，推荐使用 try-with-resources

## 多链演进

| 链 | 曲线 | HD 标准 | 默认路径 | 状态 |
|----|------|---------|----------|------|
| EVM | secp256k1 | BIP-32/44 | m/44'/60'/0'/0/0 | ✅ |
| BTC | secp256k1 | BIP-32/84 | m/84'/0'/0'/0/0 | 🚧 |
| SOL | ed25519 | SLIP-0010 | m/44'/501'/0'/0' | 🚧 |
| APTOS | ed25519 | SLIP-0010 | m/44'/637'/0'/0'/0' | 🚧 |
| NEAR | ed25519 | SLIP-0010 | m/44'/397'/0' | 🚧 |
| TRON | secp256k1 | BIP-32/44 | m/44'/195'/0'/0/0 | ✅ |
| COSMOS | secp256k1 | BIP-32/44 | m/44'/118'/0'/0/0 | 🚧 |

新增链：实现 `ChainAdapter` 并通过 SPI 注册。

## 构建

```bash
mvn compile   # 编译
mvn test      # 测试
mvn install   # 安装
```

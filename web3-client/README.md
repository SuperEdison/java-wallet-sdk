# web3-client

统一入口与账户派生工具。

## 组件

| 类 | 说明 |
|-----|------|
| `Web3Client` | SDK 入口，适配器管理 |
| `ChainAdapterRegistry` | SPI 适配器注册表 |
| `AccountDeriver` | 中心化钱包场景的账户派生 |

## Web3Client

```java
// 创建客户端（自动发现 SPI 注册的适配器）
Web3Client client = Web3Client.builder()
    .autoDiscover()
    .build();

// 检查链支持
boolean supported = client.supports(ChainType.EVM);

// 获取适配器
ChainAdapter adapter = client.adapter(ChainType.EVM);

// 创建钱包
HDWallet wallet = adapter.createHDWallet(24);

// 验证地址
boolean valid = client.isValidAddress(ChainType.EVM, "0x...");
```

## AccountDeriver

**用途**：中心化钱包/交易所为每个用户派生唯一地址。

**原理**：
- 路径：`m/44'/60'/ACCOUNT'/0/0`
- 映射：`ACCOUNT = SHA256(userId) % 2^31`

```java
// 生成主助记词（安全存储）
List<String> masterMnemonic = Bip39.generateMnemonic(24);

// 派生用户地址
String address = AccountDeriver.deriveEvmAddress(masterMnemonic, null, "user_12345");

// 派生完整结果（含签名能力）
try (DeriveResult result = AccountDeriver.deriveForUser(masterMnemonic, null, "user_12345")) {
    String addr = result.address();
    SigningKey signer = result.signingKey();
    Signature sig = signer.sign(txHash);
}  // 自动销毁私钥
```

## SPI 注册

适配器通过 SPI 自动发现：

```
META-INF/services/io.github.superedison.web3.chain.ChainAdapter
```

内容：
```
io.github.superedison.web3.chain.evm.EvmChainAdapter
```

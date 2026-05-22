# Web3 Wallet SDK (Java 21+)

模块化、安全优先的 Web3 钱包 SDK。支持 EVM、TRON、Bitcoin（P2PKH / P2SH-P2WPKH / P2WPKH）和 Solana，提供可扩展的链 SPI 和密码学原语。除本地 HD 钱包外，还可通过 **AWS KMS** 托管私钥，做生产级热钱包。Bitcoin Taproot (P2TR) 签名计划于 0.2.0 提供。

## 许可证

MIT 许可。可免费用于钱包、交易所、SaaS 及其他商业产品。

## 快速开始

### Maven 依赖

```xml
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-client</artifactId>
    <version>latest</version>
</dependency>
```

如果只需要特定链的支持，可以单独引入：

```xml
<!-- EVM (Ethereum, BSC, Polygon 等) -->
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-chain-evm</artifactId>
    <version>latest</version>
</dependency>

<!-- TRON -->
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-chain-tron</artifactId>
    <version>latest</version>
</dependency>

<!-- Bitcoin -->
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-chain-btc</artifactId>
    <version>latest</version>
</dependency>

<!-- Solana -->
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-chain-solana</artifactId>
    <version>latest</version>
</dependency>

<!-- 可选：AWS KMS 托管签名（生产热钱包） -->
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-kms</artifactId>
    <version>latest</version>
</dependency>
<!-- 同时在你自己的 pom 加上 AWS SDK 及任意一种 HTTP 客户端，详见下面的"云 KMS 热钱包"章节 -->
```

---

## 模块结构

| 模块 | 描述 |
|------|------|
| web3-core | 语义/安全抽象（RawTransaction, SignedTransaction, SigningKey, Address） |
| web3-crypto | 纯密码学（hash, Secp256k1/Ed25519, BIP-32/39/44, SecureBytes） |
| web3-chain | 链抽象（共享类型） |
| web3-chain-spi | 链 SPI（ChainAdapter, ChainType, AddressEncoder） |
| web3-chain-evm | EVM 实现（RLP 编码, Keccak 哈希, secp256k1 签名） |
| web3-chain-tron | TRON 实现（Protobuf 编码, SHA256 txid, secp256k1 签名） |
| web3-chain-btc | Bitcoin 实现（P2PKH, P2SH-P2WPKH, P2WPKH；Taproot 0.2.0） |
| web3-chain-solana | Solana 实现（Ed25519 签名, Base58 地址） |
| web3-client | 入口 + 适配器注册表 + AccountDeriver |
| web3-kms | 云 KMS 托管签名（AWS KMS：secp256k1 / Ed25519），私钥不出云 |

依赖方向（单向）：
```
web3-client                                      web3-kms（可选）
  └─► web3-chain-evm / -tron / -btc / -solana       │
          └─► web3-chain-spi ──► web3-core ◄────────┤
                                └─► web3-crypto ◄───┘
```

---

## 核心用法：AccountDeriver（推荐）

**一个助记词，派生所有链地址**。这是中心化钱包场景的推荐用法。

### 架构
```
助记词 (BIP-39)
   ↓
Seed (64 bytes)
   ↓
UnifiedHDWallet (链无关) - 只派生密钥
   ↓
AccountDeriver (client层) - userId → 派生路径 → 地址
   ↓
各链 AddressEncoder - 公钥 → 链格式地址
```

### 基本用法

```java
import io.github.superedison.web3.client.derive.AccountDeriver;
import io.github.superedison.web3.client.derive.ChainDeriveResult;
import io.github.superedison.web3.client.derive.DeriveOptions;
import io.github.superedison.web3.chain.btc.address.BtcAddressType;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.crypto.mnemonic.Bip39;

import java.util.List;

// 1. 生成或恢复助记词
List<String> mnemonic = Bip39.generateMnemonic(12);
// 或: List<String> mnemonic = List.of("abandon", "abandon", ... "about");

// 2. 创建 AccountDeriver
try (AccountDeriver deriver = AccountDeriver.fromMnemonic(mnemonic)) {

    // ========== EVM 地址（Ethereum, BSC, Polygon 等）==========
    String evmAddress = deriver.deriveAddress("user123", ChainType.EVM);
    System.out.println("EVM: " + evmAddress);  // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf

    // ========== TRON 地址 ==========
    String tronAddress = deriver.deriveAddress("user123", ChainType.TRON);
    System.out.println("TRON: " + tronAddress);  // TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW

    // ========== Solana 地址（自动使用 SLIP-10 Ed25519）==========
    String solAddress = deriver.deriveAddress("user123", ChainType.SOL);
    System.out.println("Solana: " + solAddress);  // 4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM

    // ========== Bitcoin 地址（多种类型）==========
    // Native SegWit (P2WPKH) - 默认
    String btcSegwit = deriver.deriveAddress("user123", ChainType.BTC);
    System.out.println("BTC SegWit: " + btcSegwit);  // bc1q...

    // Wrapped SegWit (P2SH-P2WPKH)
    DeriveOptions wrappedOpts = DeriveOptions.builder()
        .btcAddressType(BtcAddressType.P2SH_P2WPKH)
        .btcNetwork(BtcNetwork.MAINNET)
        .build();
    String btcWrapped = deriver.deriveAddress("user123", ChainType.BTC, wrappedOpts);
    System.out.println("BTC Wrapped SegWit: " + btcWrapped);  // 3...

    // Taproot (P2TR) — ⏳ 0.2.0
    // 派生入口已禁用：完整 BIP-340 Schnorr / BIP-341 sighash 签名能力计划于 0.2.0 提供。
    // 0.1.0 调用 deriver.deriveAddress(..., P2TR) 会抛 UnsupportedOperationException，
    // 避免派生出 bc1p... 但花不出去的地址。

    // Legacy (P2PKH)
    DeriveOptions legacyOpts = DeriveOptions.builder()
        .btcAddressType(BtcAddressType.P2PKH)
        .build();
    String btcLegacy = deriver.deriveAddress("user123", ChainType.BTC, legacyOpts);
    System.out.println("BTC Legacy: " + btcLegacy);  // 1...
}
```

### 获取签名密钥

```java
try (AccountDeriver deriver = AccountDeriver.fromMnemonic(mnemonic)) {
    // deriveForUser 返回完整结果，包含签名密钥
    try (ChainDeriveResult result = deriver.deriveForUser("user123", ChainType.EVM)) {
        String address = result.address();

        // 使用 SigningKey 签名交易
        byte[] txHash = /* 交易哈希 */ new byte[32];
        byte[] signature = result.signingKey().sign(txHash);

        System.out.println("地址: " + address);
        System.out.println("签名: " + bytesToHex(signature));
    } // SigningKey 自动销毁
}
```

### 批量派生

```java
try (AccountDeriver deriver = AccountDeriver.fromMnemonic(mnemonic)) {
    // 批量派生地址（只获取地址，不返回私钥）
    List<String> addresses = deriver.deriveAddresses(ChainType.EVM, 0, 10);

    // 批量派生完整结果（包含签名密钥）
    List<ChainDeriveResult> results = deriver.deriveRange(ChainType.EVM, 0, 10);
    for (ChainDeriveResult result : results) {
        System.out.println(result.accountIndex() + ": " + result.address());
        result.close(); // 记得销毁
    }
}
```

### userId 到 accountIndex 映射

```java
// 中心化钱包场景：userId → accountIndex
int accountIndex = AccountDeriver.userIdToAccountIndex("user123");
// 算法：SHA256(userId) → 取前4字节 → 转为无符号整数 → % 2^31

// 同一个 userId 始终映射到相同的 accountIndex
assert AccountDeriver.userIdToAccountIndex("user123")
    == AccountDeriver.userIdToAccountIndex("user123");
```

### 静态路径工具

```java
// 获取各链的标准派生路径
String evmPath = AccountDeriver.getPathForChain(ChainType.EVM, 0);
// m/44'/60'/0'/0/0

String tronPath = AccountDeriver.getPathForChain(ChainType.TRON, 0);
// m/44'/195'/0'/0/0

String solPath = AccountDeriver.getPathForChain(ChainType.SOL, 0);
// m/44'/501'/0'/0' (Ed25519 使用硬化路径)

// 获取 BTC 特定地址类型的路径
String btcSegwitPath = AccountDeriver.getPathForBtcType(BtcAddressType.P2WPKH, 0);
// m/84'/0'/0'/0/0

String btcWrappedPath = AccountDeriver.getPathForBtcType(BtcAddressType.P2SH_P2WPKH, 0);
// m/49'/0'/0'/0/0

// P2TR (Taproot) 路径在 0.1.0 暂未开放——getPathForBtcType(P2TR, ...) 会抛
// UnsupportedOperationException，与派生入口保持一致。
```

---

## 底层用法：直接使用 Bip32/Bip39

如果你需要更底层的控制，可以直接使用密码学原语：

```java
import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

// 1. 生成或恢复助记词
List<String> mnemonic = Bip39.generateMnemonic(12);

// 2. 派生种子
byte[] seed = Bip39.mnemonicToSeed(mnemonic, "");

// 3. 为每条链派生密钥并生成地址
public void generateUserAddresses(byte[] seed) {

    // ========== EVM (Ethereum, BSC, Polygon 等) ==========
    // BIP-44 路径: m/44'/60'/0'/0/0
    byte[] evmKey = Bip32.derivePath(seed, "m/44'/60'/0'/0/0").getPrivateKey();
    try (Secp256k1Signer signer = new Secp256k1Signer(evmKey)) {
        EvmAddress evmAddr = EvmAddress.fromPublicKey(signer.getPublicKey());
        System.out.println("EVM 地址: " + evmAddr.toChecksumHex());
    }

    // ========== TRON ==========
    // BIP-44 路径: m/44'/195'/0'/0/0
    byte[] tronKey = Bip32.derivePath(seed, "m/44'/195'/0'/0/0").getPrivateKey();
    try (Secp256k1Signer signer = new Secp256k1Signer(tronKey)) {
        TronAddress tronAddr = TronAddress.fromPublicKey(signer.getPublicKey());
        System.out.println("TRON 地址: " + tronAddr.toBase58());
    }

    // ========== Bitcoin（多种地址类型）==========
    byte[] btcKey = Bip32.derivePath(seed, "m/84'/0'/0'/0/0").getPrivateKey();
    try (Secp256k1Signer signer = new Secp256k1Signer(btcKey)) {
        byte[] pubKey = signer.getCompressedPublicKey();

        // Legacy P2PKH（以 '1' 开头）
        P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET);
        System.out.println("BTC Legacy (P2PKH): " + p2pkh.toBase58());

        // Wrapped SegWit P2SH-P2WPKH（以 '3' 开头）
        P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(pubKey, BtcNetwork.MAINNET);
        System.out.println("BTC Wrapped SegWit (P2SH): " + p2sh.toBase58());

        // Native SegWit P2WPKH（以 'bc1q' 开头）
        Bech32Address bech32 = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.MAINNET);
        System.out.println("BTC Native SegWit (P2WPKH): " + bech32.toBech32());

        // ⚠️ Taproot P2TR：低层工具类 TaprootAddress 仍可用于解析 / 实验，
        // 但 0.1.0 的 BtcChainAdapter 还无法签名 P2TR 输入。生产请等 0.2.0。
    }

    // ========== Solana ==========
    // BIP-44 路径: m/44'/501'/0'/0' (Ed25519)
    byte[] solKey = Bip32.derivePath(seed, "m/44'/501'/0'/0'").getPrivateKey();
    try (Ed25519Signer signer = new Ed25519Signer(solKey)) {
        SolanaAddress solAddr = SolanaAddress.fromPublicKey(signer.getPublicKey());
        System.out.println("Solana 地址: " + solAddr.toBase58());
    }
}
```

### 从私钥快速生成地址

```java
// Bitcoin - 从单个密钥生成所有地址类型
byte[] privateKey = new byte[32]; // 你的 32 字节私钥

try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
    byte[] pubKey = signer.getCompressedPublicKey();

    // 生成 0.1.0 可签名的 Bitcoin 地址类型
    String legacy   = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET).toBase58();
    String wrapped  = P2SHAddress.fromPublicKeyP2WPKH(pubKey, BtcNetwork.MAINNET).toBase58();
    String segwit   = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.MAINNET).toBech32();
    // P2TR：低层 TaprootAddress 类可用，但签名能力 0.2.0 才提供，0.1.0 不要往派生出来的 bc1p 地址收币。
}

// Solana - Ed25519
try (Ed25519Signer signer = new Ed25519Signer(privateKey)) {
    String solanaAddr = SolanaAddress.fromPublicKey(signer.getPublicKey()).toBase58();
}
```

### 地址验证与解析

```java
// Bitcoin - 解析任意地址类型
BtcAddress addr = BtcAddress.fromString("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
System.out.println("类型: " + addr.getType());     // P2WPKH
System.out.println("网络: " + addr.getNetwork());  // MAINNET

// 验证地址
boolean isValidBtc = BtcAddress.isValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); // true
boolean isValidSol = SolanaAddress.isValid("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"); // true

// 检测 Bitcoin 地址类型
BtcAddressType type = BtcAddressType.fromAddress("bc1p...");  // P2TR (Taproot)
BtcNetwork network = BtcNetwork.fromAddress("tb1q...");       // TESTNET
```

---

## 云 KMS 热钱包（可选）

当私钥不能落到应用进程里时（合规、多副本服务、审计需求），可用 `web3-kms` 把签名委托给 **AWS KMS**：私钥永远在 KMS 内，应用只调 `Sign` API。所有 KMS 签名密钥都实现了同一个 `SigningKey` 接口，**与现有 `ChainAdapter` / `AccountDeriver` 完全兼容**——任何能接 `SigningKey` 的位置都能换成 KMS 版本。

### 支持矩阵

| 链 | KMS KeySpec | 算法 |
|----|------|------|
| EVM (Ethereum / BSC / Polygon …) | `ECC_SECG_P256K1` | ECDSA SHA-256（v 由公钥反算） |
| TRON | `ECC_SECG_P256K1` | 同上 |
| Solana | `ECC_NIST_EDWARDS25519` | Ed25519（KMS `ED25519_SHA_512`，AWS 2025 年加） |

KMS 是**热钱包模式**，不是 HD 钱包——每个 KMS Key 是一个独立账户，靠 KeyId / Alias / ARN 寻址；如果需要"一个助记词 → 多链多用户"派生，继续用 `AccountDeriver`。

### Maven 依赖

在你自己的应用 `pom.xml` 里：

```xml
<dependency>
    <groupId>io.github.superedison</groupId>
    <artifactId>web3-kms</artifactId>
    <version>latest</version>
</dependency>

<!-- AWS KMS SDK（web3-kms 把它声明为 optional，需要你显式引入） -->
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>kms</artifactId>
    <version>2.44.11</version>  <!-- AWS SDK version, independent of web3-kms -->
</dependency>

<!-- 二选一：AWS SDK 的 HTTP 客户端实现 -->
<!-- 推荐：轻量、零 logging 依赖 -->
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>url-connection-client</artifactId>
    <version>2.44.11</version>  <!-- AWS SDK version, independent of web3-kms -->
</dependency>
<!-- 或保留 Apache HttpClient（kms 默认），但要补 commons-logging：
<dependency><groupId>commons-logging</groupId><artifactId>commons-logging</artifactId><version>1.2</version></dependency>
-->
```

### 构造 KmsClient

`web3-kms` 不对 `KmsClient` 做封装——直接用 AWS SDK 原生 builder 即可。凭证来源按推荐度由高到低：

| 方式 | 写法 | 适用场景 |
|------|------|------|
| **IAM Role / 实例 Profile** | `KmsClient.builder().region(R).build()`（不传 credentialsProvider） | ✅ 生产首选，零密钥落地 |
| **环境变量 / `~/.aws/credentials`** | 同上，SDK 走默认凭证链查找 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | 本地开发 |
| **静态 AK/SK** | 见下方代码 | 临时调试 / 多租户（每租户一套 KMS Key + 一套 AK） |
| **STS 临时凭证** | `AwsSessionCredentials.create(ak, sk, sessionToken)` | 跨账号 / 短期授权 |
| **自定义 Provider**（如 SecretManager 拉取） | 实现 `AwsCredentialsProvider` 接口 | 复杂凭证轮转策略 |

```java
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

// 生产推荐：不传 credentialsProvider，走默认凭证链（IAM Role / 实例 Profile / 环境变量）
KmsClient kms = KmsClient.builder()
        .region(Region.AP_SOUTHEAST_1)
        .build();

// 调试 / 多租户：显式 AK/SK
KmsClient kmsDebug = KmsClient.builder()
        .region(Region.US_EAST_1)
        .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(System.getenv("AWS_AK"), System.getenv("AWS_SK"))))
        .build();

// LocalStack / 私有部署
KmsClient kmsLocal = KmsClient.builder()
        .region(Region.US_EAST_1)
        .endpointOverride(java.net.URI.create("http://localhost:4566"))
        .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create("test", "test")))
        .build();
```

> ⚠️ AK/SK 是热钱包私钥级别的凭证，**不要进 git**。生产用 IAM Role / SecretManager / K8s Secret。
>
> 💡 `KmsClient` 线程安全，多个 `SigningKey` 应共享同一个 client，省连接和 STS 刷新成本。

### 统一抽象：所有签名入口都收 `SigningKey`

从 `0.1.0` 起，业务层 API（消息签名、链特定 Signer、Wallet 等）**一律收 `SigningKey`**，本地私钥和 KMS Key 走同一套入口：

```java
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.kms.aws.AwsKmsSecp256k1Key;

// 本地私钥
try (SigningKey local = new Secp256k1Signer(privateKey)) { /* ... */ }

// KMS 托管 —— 同样是 SigningKey
try (SigningKey kms = new AwsKmsSecp256k1Key(kmsClient, "alias/eth-hot")) { /* ... */ }
```

任何能写 `SigningKey` 的地方，本地和 KMS 完全可互换。

### 用 AWS KMS 签 EVM / TRON 交易

```java
import io.github.superedison.web3.chain.evm.EvmChainAdapter;
import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.message.EvmMessageSigner;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.wallet.EvmWallet;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.kms.aws.AwsKmsSecp256k1Key;

try (SigningKey kmsKey = new AwsKmsSecp256k1Key(kms, "alias/eth-hot")) {

    // ① 直接派生地址
    EvmAddress addr = EvmAddress.fromPublicKey(kmsKey.getPublicKey());

    // ② 签交易：ChainAdapter 不知道也不关心私钥在哪
    EvmRawTransaction tx = EvmRawTransaction.builder()
            .nonce(1).gasPrice(java.math.BigInteger.valueOf(20_000_000_000L))
            .gasLimit(21_000).to("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE7")
            .value(java.math.BigInteger.valueOf(1_000_000_000_000_000_000L))
            .chainId(1).build();
    var adapter = new EvmChainAdapter();
    var signed = adapter.sign(tx, kmsKey);
    byte[] rawBytes = adapter.rawBytes(signed);   // 广播字节

    // ③ EIP-191 personal_sign：同一个 kmsKey
    Signature msgSig = EvmMessageSigner.signMessage("hello dapp", kmsKey);

    // ④ 想要 Wallet 抽象（KMS 钱包，无 KeyHolder）：
    EvmWallet wallet = new EvmWallet("hot-1", kmsKey);
    assert wallet.getKeyHolder().isEmpty();  // 远程托管，不可导出私钥
}
```

TRON 一模一样，类名前缀换成 `Tron`，KMS Key 的 KeySpec 仍是 `ECC_SECG_P256K1`。

### 用 AWS KMS 签 Solana 交易

```java
import io.github.superedison.web3.chain.solana.SolanaChainAdapter;
import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.kms.aws.AwsKmsEd25519Key;

try (SigningKey kmsKey = new AwsKmsEd25519Key(kms, "alias/sol-hot")) {
    SolanaAddress addr = SolanaAddress.fromPublicKey(kmsKey.getPublicKey());

    // 跟前面 Solana 章节一样构造 SolanaRawTransaction，再 adapter.sign(tx, kmsKey)
}
```

### IAM 权限最小集

热钱包用的 IAM 角色至少需要这两个 KMS 动作（绑到具体 KeyId 上，别开 `*`）：

```json
{
  "Effect": "Allow",
  "Action": ["kms:GetPublicKey", "kms:Sign"],
  "Resource": "arn:aws:kms:ap-southeast-1:123456789012:key/<your-key-id>"
}
```

### 注意事项

- **延迟**：每笔签名一次 KMS 网络调用（同区域 < 50ms），高 TPS 场景关注 KMS 请求配额（默认每秒 ~10k，可申请）。
- **v 计算（EVM/TRON）**：KMS 返回 DER `(r, s)`，模块内部用缓存公钥反算 `v ∈ [0,3]`，再由现有适配器叠 EIP-155。
- **destroy() 语义**：私钥在 AWS，`close()` 只清本地公钥缓存；KMS 不"删除"密钥（要删走 AWS 的 `ScheduleKeyDeletion`）。
- **KmsClient 复用**：线程安全，多个 `SigningKey` 共享一个 `KmsClient` 即可。
- **备份**：KMS Key 丢失 = 资产丢失。生产配多区域 Key / 跨账号备份策略。

---

## 交易签名

### EVM 交易

```java
import io.github.superedison.web3.chain.evm.EvmChainAdapter;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.tx.EvmSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import java.math.BigInteger;

// 1) 构建交易意图
EvmRawTransaction tx = EvmRawTransaction.builder()
        .nonce(1)
        .gasPrice(BigInteger.valueOf(20_000_000_000L))
        .gasLimit(21_000)
        .to("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE7")
        .value(BigInteger.valueOf(1_000_000_000_000_000_000L))
        .chainId(1)
        .build();

// 2) 选择适配器（或使用 ServiceLoader 自动发现）
ChainAdapter<EvmRawTransaction, EvmSignedTransaction> adapter = new EvmChainAdapter();

// 3) 使用 secp256k1 私钥签名
byte[] privateKey = /* 你的 32 字节 secp256k1 私钥 */ new byte[32];
try (Secp256k1Signer key = new Secp256k1Signer(privateKey)) {
    EvmSignedTransaction signed = adapter.sign(tx, key);
    byte[] rawBytes = adapter.rawBytes(signed); // 广播字节
    byte[] txHash   = adapter.txHash(signed);   // 交易哈希
}
```

### TRON 交易

```java
import io.github.superedison.web3.chain.tron.TronChainAdapter;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

// 构建交易意图（转账）
TronRawTransaction tx = TronRawTransaction.builder()
        .from("T...")                  // 发送方（Base58）
        .to("T...")                    // 接收方（Base58）
        .amount(1_000_000)             // sun
        .refBlockBytes(new byte[]{0x00, 0x01})
        .refBlockHash(new byte[8])
        .expiration(System.currentTimeMillis() + 600_000)
        .timestamp(System.currentTimeMillis())
        .feeLimit(10_000_000)
        .build();

ChainAdapter<TronRawTransaction, TronSignedTransaction> adapter = new TronChainAdapter();

try (Secp256k1Signer key = new Secp256k1Signer(/* 32 字节私钥 */ new byte[32])) {
    TronSignedTransaction signed = adapter.sign(tx, key);
    byte[] rawBytes = adapter.rawBytes(signed); // 广播字节
    byte[] txHash   = adapter.txHash(signed);   // txid (SHA256(raw_data))
}
```

### Bitcoin 交易

```java
import io.github.superedison.web3.chain.btc.BtcChainAdapter;
import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

// 构建交易
byte[] prevTxHash       = /* 32 字节前一笔交易哈希 */ new byte[32];
byte[] prevScriptPubKey = /* 被花费 UTXO 的 scriptPubKey (P2WPKH 或 P2SH-P2WPKH) */ new byte[22];
long   prevAmount       = 100_000L;   // 被花费 UTXO 的金额（聪），SegWit 签名必填（BIP-143）
byte[] recipientScript  = /* 接收方的 scriptPubKey */ new byte[25];

BtcRawTransaction tx = BtcRawTransaction.builder()
        .version(2)
        .segwit(true)                                                 // 启用 SegWit
        // 4 参重载携带 amount + scriptPubKey；2 参的简化重载不能配合 segwit=true，会被签名器拒绝
        .addInput(prevTxHash, 0, prevAmount, prevScriptPubKey)
        .addOutput(50000L, recipientScript)                           // 50000 satoshis
        .lockTime(0)
        .build();

// 签名
BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
try (Secp256k1Signer key = new Secp256k1Signer(/* 32 字节私钥 */ new byte[32])) {
    BtcSignedTransaction signed = adapter.sign(tx, key);
    String txHex = signed.encodeHex();      // 广播 hex
    String txid = signed.txHashHex();       // 交易 ID
}
```

### Solana 交易

```java
import io.github.superedison.web3.chain.solana.SolanaChainAdapter;
import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaSignedTransaction;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;

import java.util.List;

// System Program ID（用于转账）
byte[] SYSTEM_PROGRAM = new byte[32];

// 构建交易
byte[] recentBlockhash = /* 32 字节最近区块哈希 */ new byte[32];
byte[] feePayer = /* 32 字节费用支付者公钥 */ new byte[32];

SolanaRawTransaction tx = SolanaRawTransaction.builder()
        .recentBlockhash(recentBlockhash)
        .feePayer(feePayer)
        .addAccount(feePayer, true, true)   // 签名者，可写
        .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
        .build();

// 使用 Ed25519 签名
SolanaChainAdapter adapter = new SolanaChainAdapter();
try (Ed25519Signer key = new Ed25519Signer(/* 32 字节私钥 */ new byte[32])) {
    SolanaSignedTransaction signed = adapter.sign(tx, key);
    String base64Tx = signed.encodeBase64();    // 用于 RPC 提交
    String signature = signed.signatureBase58(); // 交易签名
}
```

---

## 链扩展（SPI）

- 接口：`io.github.superedison.web3.chain.spi.ChainAdapter`
- SPI 文件：`META-INF/services/io.github.superedison.web3.chain.spi.ChainAdapter`
- EVM 示例：组合 `TransactionEncoder` (RLP) + `TransactionHasher` (Keccak) + `TransactionSigner` (secp256k1)
- TRON 示例：组合 `TransactionEncoder` (Protobuf raw_data) + `TransactionHasher` (SHA256 raw_data) + `TransactionSigner` (secp256k1)
- BTC 示例：组合 `TransactionEncoder` (Bitcoin 序列化) + `TransactionHasher` (双重 SHA256) + `TransactionSigner` (secp256k1)
- Solana 示例：组合 `TransactionEncoder` (compact array) + `TransactionSigner` (Ed25519)

要添加新链：实现 `ChainAdapter`，定义你的 Raw/SignedTransaction，实现 encoder/hasher/signer，然后通过 SPI 注册。

---

## 多链支持

| 链 | 曲线 | 默认路径 | 地址类型 | 状态 |
|----|------|----------|----------|------|
| EVM | secp256k1 | m/44'/60'/0'/0/0 | 0x...（EIP-55 校验和） | 已完成 |
| TRON | secp256k1 | m/44'/195'/0'/0/0 | T...（Base58Check） | 已完成 |
| Bitcoin | secp256k1 | m/84'/0'/0'/0/0 | P2PKH, P2SH-P2WPKH, P2WPKH | 0.1.0 ✅ ｜ P2TR ⏳ 0.2.0 |
| Solana | Ed25519 | m/44'/501'/0'/0' | Base58（32 字节） | 已完成 |
| Cosmos | secp256k1 | m/44'/118'/0'/0/0 | cosmos1... | 计划中 |
| Aptos | Ed25519 | m/44'/637'/0'/0'/0' | 0x... | 计划中 |
| NEAR | Ed25519 | m/44'/397'/0' | ... | 计划中 |

## Bitcoin 地址类型（0.1.0 支持矩阵）

| 类型 | 前缀 | BIP | 派生 | 签名（花费） | 备注 |
|------|------|-----|:----:|:----:|------|
| P2PKH | 1（主网），m/n（测试网） | BIP-44 | ✅ | ✅ | Legacy 地址 |
| P2SH-P2WPKH | 3（主网），2（测试网） | BIP-49 | ✅ | ✅ | Wrapped SegWit；input 需提供 `amount` + P2SH `scriptPubKey` |
| P2WPKH | bc1q（主网），tb1q（测试网） | BIP-84 | ✅ | ✅ | Native SegWit；input 需提供 `amount` |
| P2WSH | bc1q（主网），tb1q（测试网） | BIP-84 | ⚠️ 仅地址类工具 | ❌ | 需脚本而非公钥，未在 deriver 暴露 |
| P2TR | bc1p（主网），tb1p（测试网） | BIP-86 | ⏳ 0.2.0 | ⏳ 0.2.0 | 签名（BIP-340 Schnorr + BIP-341 sighash）未实现，**派生入口已禁用**避免用户丢币 |

> ⚠️ **SegWit 输入 `amount` 必填**：BIP-143 签名哈希必须包含被花费 UTXO 的金额。0.1.0 起，`addInput(prevTxHash, idx)` 简化重载（amount=0）配合 segwit 路径会**直接抛异常**。请用 `addInput(prevTxHash, idx, amount, scriptPubKey)` 重载。

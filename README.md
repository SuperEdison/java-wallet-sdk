# Web3 Wallet SDK (Java 21+)

模块化、安全优先的 Web3 钱包 SDK。支持 EVM、TRON、Bitcoin（全地址类型）和 Solana，提供可扩展的链 SPI 和密码学原语。

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
| web3-chain-btc | Bitcoin 实现（P2PKH, P2SH, SegWit, Taproot） |
| web3-chain-solana | Solana 实现（Ed25519 签名, Base58 地址） |
| web3-client | 入口 + 适配器注册表 + AccountDeriver |

依赖方向（单向）：
```
web3-client
  └─► web3-chain-evm / web3-chain-tron / web3-chain-btc / web3-chain-solana
          └─► web3-chain-spi ──► web3-core
                                └─► web3-crypto
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

    // Taproot (P2TR)
    DeriveOptions taprootOpts = DeriveOptions.builder()
        .btcAddressType(BtcAddressType.P2TR)
        .btcNetwork(BtcNetwork.MAINNET)
        .build();
    String btcTaproot = deriver.deriveAddress("user123", ChainType.BTC, taprootOpts);
    System.out.println("BTC Taproot: " + btcTaproot);  // bc1p...

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
String btcTaprootPath = AccountDeriver.getPathForBtcType(BtcAddressType.P2TR, 0);
// m/86'/0'/0'/0/0

String btcSegwitPath = AccountDeriver.getPathForBtcType(BtcAddressType.P2WPKH, 0);
// m/84'/0'/0'/0/0
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

        // Taproot P2TR（以 'bc1p' 开头）
        TaprootAddress taproot = TaprootAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET);
        System.out.println("BTC Taproot (P2TR): " + taproot.toBech32m());
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

    // 生成所有 Bitcoin 地址类型
    String legacy   = P2PKHAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET).toBase58();
    String wrapped  = P2SHAddress.fromPublicKeyP2WPKH(pubKey, BtcNetwork.MAINNET).toBase58();
    String segwit   = Bech32Address.p2wpkhFromPublicKey(pubKey, BtcNetwork.MAINNET).toBech32();
    String taproot  = TaprootAddress.fromPublicKey(pubKey, BtcNetwork.MAINNET).toBech32m();
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
byte[] prevTxHash = /* 32 字节前一笔交易哈希 */ new byte[32];
byte[] recipientScript = /* 接收方的 scriptPubKey */ new byte[25];

BtcRawTransaction tx = BtcRawTransaction.builder()
        .version(2)
        .addInput(prevTxHash, 0)           // UTXO 引用
        .addOutput(50000L, recipientScript) // 50000 satoshis
        .lockTime(0)
        .segwit(true)                       // 启用 SegWit
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
| Bitcoin | secp256k1 | m/84'/0'/0'/0/0 | P2PKH, P2SH, P2WPKH, P2WSH, P2TR | 已完成 |
| Solana | Ed25519 | m/44'/501'/0'/0' | Base58（32 字节） | 已完成 |
| Cosmos | secp256k1 | m/44'/118'/0'/0/0 | cosmos1... | 计划中 |
| Aptos | Ed25519 | m/44'/637'/0'/0'/0' | 0x... | 计划中 |
| NEAR | Ed25519 | m/44'/397'/0' | ... | 计划中 |

## Bitcoin 地址类型

| 类型 | 前缀 | BIP | 描述 |
|------|------|-----|------|
| P2PKH | 1（主网），m/n（测试网） | BIP-44 | Legacy 地址 |
| P2SH-P2WPKH | 3（主网），2（测试网） | BIP-49 | Wrapped SegWit |
| P2WPKH | bc1q（主网），tb1q（测试网） | BIP-84 | Native SegWit |
| P2WSH | bc1q（主网），tb1q（测试网） | BIP-84 | Native SegWit Script |
| P2TR | bc1p（主网），tb1p（测试网） | BIP-86 | Taproot |

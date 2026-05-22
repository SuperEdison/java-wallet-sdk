# 更新日志

本项目遵循语义化版本（SemVer）。

## [0.1.0] - 2026-05-22

> ⚠️ **从 0.0.4 升级请先看本节"💥 BREAKING CHANGES"——本次有源代码不兼容的 API 变更，旧调用会编译失败。**

### 💥 BREAKING CHANGES（升级必读）

1. **私钥不再以 `byte[]` 形式跨入业务层 API，统一收 `SigningKey`**。
   - `EvmMessageSigner.signMessage / signHash`、`TronMessageSigner.signMessage / signHash`：第二参数 `byte[] privateKey` → `SigningKey signingKey`。
   - `EvmSigner` / `TronSigner` 构造器：`byte[] privateKey` → `SigningKey signingKey`，且改为**非拥有式**（不接管底层 SigningKey 生命周期，允许多个 Signer 复用同一个 KMS Key）。
   - 升级路径——把现有 `byte[] sk` 包一层：
     - 本地：`new Secp256k1Signer(sk)` 或 `new Ed25519Signer(sk)`
     - KMS：`new AwsKmsSecp256k1Key(kms, keyId)` / `new AwsKmsEd25519Key(kms, keyId)`
     - 这两类都实现 `SigningKey`，传给业务层方法 / 构造器即可。
2. **`Wallet.getKeyHolder()` 返回类型从 `KeyHolder` 改为 `Optional<KeyHolder>`**。
   - 远程托管钱包（KMS / HSM / 硬件钱包）返回 `Optional.empty()`——它们没有可导出的字节。
   - 旧调用 `wallet.getKeyHolder().exportPrivateKey()` 升级为 `wallet.getKeyHolder().orElseThrow().exportPrivateKey()`，或 `wallet.getKeyHolder().ifPresent(...)`。
3. **BTC SegWit 签名输入必须提供 `amount > 0`**（详见下方"修复"小节）。先前默认 `amount=0` 会签出无效交易，现在直接抛 `IllegalArgumentException`——这是为防止资金损失的故意 breaking。
4. **BTC P2TR（Taproot）派生入口已禁用**：`BtcAddressEncoder.encode(P2TR, ...)` / `AccountDeriver.getPathForBtcType(P2TR, ...)` 抛 `UnsupportedOperationException`。详见"推迟到 0.2.0"。
5. **Solana 仅支持单 signer 交易**：多 signer 交易调用 `adapter.sign(tx, key)` 会抛 `UnsupportedOperationException`。

### 新增
- **新增 `web3-kms` 模块**：支持云 KMS 托管签名作为生产级热钱包方案。
  - AWS KMS：`AwsKmsSecp256k1Key`（EVM / TRON，`ECC_SECG_P256K1`）与 `AwsKmsEd25519Key`（Solana，`ECC_NIST_EDWARDS25519` + `ED25519_SHA_512`）。
  - 私钥永远不离开 AWS，应用只调 `Sign` API。
  - `KmsClient` 直接使用 AWS SDK 原生 builder 构造，不再包一层；凭证支持 IAM Role / 默认链 / 静态 AK+SK / STS / 自定义 `AwsCredentialsProvider`。
  - 共享工具 `DerSignatures`（DER → r/s + low-S 规范化）、`SubjectPublicKeyInfos`（X.509 SPKI 解析）；EVM 的 `v` 由公钥反算。
  - 仅 AWS。Google Cloud KMS / Azure Key Vault 计划在后续版本提供。
- `EvmWallet` / `TronWallet` 新增 `(String id, SigningKey signingKey)` 构造器，用于 KMS / HSM 等远程托管私钥的钱包场景。
- AWS SDK 依赖：建议下游同时引入 `software.amazon.awssdk:url-connection-client`（推荐，轻量、零 commons-logging 依赖）或自行补 `commons-logging`。

### 修复（**资金安全相关**）
- **BTC P2SH-P2WPKH 包裹 SegWit 现在能正确花费**：之前签名器只按原生 P2WPKH 处理，没有给输入设置 redeemScript scriptSig，导致从 `3...` 地址花币的交易无效。修复后会检测 input.scriptPubKey() 的 P2SH 模式（OP_HASH160 0x14 ... OP_EQUAL），自动写入 22 字节 redeemScript (`0x16 0x00 0x14 hash160(pubkey)`) 到 scriptSig，witness 不变。
- **BTC P2SH 模式严格校验**：仅当 P2SH scriptPubKey 中的 20-byte hash 等于 `hash160(0x00 0x14 hash160(pubkey))` 才按 P2SH-P2WPKH 处理；不匹配（如普通 P2SH 多签或其他 redeemScript）直接抛 `IllegalArgumentException`，避免静默签出无效交易。
- **BTC SegWit 输入要求 amount > 0**：BIP-143 签名哈希必须包含被花费 UTXO 的金额，amount=0 会签出无效交易。之前 `addInput(prevTxHash, prevOutputIndex)` 简化重载默认 amount=0 静默放行，现在 SegWit 签名路径会拒绝 amount ≤ 0，错误信息明确指向 `addInput(prevTxHash, prevOutputIndex, amount, scriptPubKey)` 重载。
- **Solana 仅支持单 signer 交易（暂时）**：之前签名器只写一个签名，但消息头会根据账户的 `isSigner` 标志统计 `numRequiredSignatures`，多 signer 交易会序列化成无效字节。现在签名前会检查 `numRequiredSignatures == 1`，否则抛 `UnsupportedOperationException`。

### 推迟到 0.2.0
- **BTC P2TR（Taproot）地址派生 + 签名**：`BtcAddressEncoder.encode(P2TR)` 和 `AccountDeriver.getPathForBtcType(P2TR)` 抛 `UnsupportedOperationException`。原因是签名侧 BIP-340 Schnorr / BIP-341 sighash 尚未实现，派生出 `bc1p...` 地址会导致用户花不出币。低层工具类 `TaprootAddress.fromPublicKey()` 保留，但用户需自担风险。
- **Solana 多 signer API**：完整设计与实现留到 0.2.0。
- **Google Cloud KMS / Azure Key Vault**：`web3-kms` 仅 AWS。

### 文档
- README 新增"云 KMS 热钱包（可选）"章节：包含 Maven 引入、原生 `KmsClient.builder()` 用法、IAM 最小权限策略、本地 / KMS 同一入口的代码示例。
- README 的 BTC 地址类型矩阵明确区分"派生 / 签名"两栏，标注 P2TR ⏳ 0.2.0、P2WSH 仅地址类工具。
- `web3-chain-btc/README.md` 同步 0.1.0 支持矩阵。

## [0.0.4] - 2026-03-02

### 新增
- 新增统一 secp256k1 `v` 归一化工具 `Secp256k1VNormalizer`，统一处理 `0/1`、`27/28` 与 EIP-155 场景。
- 新增测试向量目录 `web3-client/src/test/resources/test-vectors/`，包含：
  - `secp256k1_v_normalization.csv`
  - `account_index_mapping.csv`
- 新增跨语言向量测试 `CrossLanguageVectorTest`。
- 新增 EIP-155 安全回归测试 `EvmEip155SafetyTest`。

### 变更
- EVM 与 TRON 签名模块改为复用统一 `v` 归一化逻辑，避免链间与实现间分叉行为。
- EVM 交易编码默认按 EIP-155 规则构造签名载荷（包含 `[chainId, 0, 0]`）。
- EVM 原始交易构建器强制 `chainId > 0`。
- 所有 Maven 模块版本统一更新为 `0.0.4`。

### 修复
- 修复 `UnifiedHDWallet.fromMnemonic` 中临时种子清理导致的潜在可用性问题。
- 修复 `UnifiedHDWallet.deriveRange` 在替换末级索引时丢失 hardened 后缀（`'` / `H`）的问题。
- 清理重复测试注解，消除测试层不稳定因素。

### 测试
- 增加同一 master seed 多实例派生一致性、并发一致性、销毁隔离与输入防御性拷贝测试。
- 增加 client 层 `fromSeed` 派生回归测试。

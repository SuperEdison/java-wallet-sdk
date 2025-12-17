package io.github.superedison.web3.client.derive;

import io.github.superedison.web3.chain.btc.BtcAddressEncoder;
import io.github.superedison.web3.chain.btc.address.BtcAddressType;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.spi.AddressEncoder;
import io.github.superedison.web3.chain.spi.AddressEncoderRegistry;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.hash.Sha256;
import io.github.superedison.web3.crypto.kdf.Bip44;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;
import io.github.superedison.web3.crypto.wallet.DerivedKey;
import io.github.superedison.web3.crypto.wallet.DerivationScheme;
import io.github.superedison.web3.crypto.wallet.UnifiedHDWallet;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * 多链账户派生工具
 *
 * 支持从一个助记词/种子派生所有链的地址：
 * - EVM (Ethereum, Polygon, BSC 等)
 * - TRON
 * - BTC (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
 * - Solana
 *
 * 核心能力：
 * - userId → accountIndex 映射（中心化钱包场景）
 * - 多链地址派生
 * - 签名密钥获取
 *
 * 使用示例：
 * <pre>{@code
 * List<String> mnemonic = Bip39.generateMnemonic(12);
 *
 * try (AccountDeriver deriver = AccountDeriver.fromMnemonic(mnemonic)) {
 *
 *     // EVM 地址
 *     try (ChainDeriveResult result = deriver.deriveForUser("user123", ChainType.EVM)) {
 *         String address = result.address();  // 0x...
 *         Signature sig = result.signingKey().sign(txHash);
 *     }
 *
 *     // BTC Taproot 地址
 *     DeriveOptions opts = DeriveOptions.builder()
 *         .btcAddressType(BtcAddressType.P2TR)
 *         .build();
 *     String btcAddress = deriver.deriveAddress("user123", ChainType.BTC, opts);
 *
 *     // Solana 地址
 *     String solAddress = deriver.deriveAddress("user123", ChainType.SOL);
 * }
 * }</pre>
 */
public final class AccountDeriver implements AutoCloseable {

    /**
     * 最大账户索引 (2^31 - 1)
     */
    private static final long MAX_ACCOUNT_INDEX = 0x7FFFFFFFL;

    private final UnifiedHDWallet hdWallet;
    private volatile boolean destroyed = false;

    private AccountDeriver(UnifiedHDWallet hdWallet) {
        this.hdWallet = hdWallet;
    }

    // ==================== 工厂方法 ====================

    /**
     * 从助记词创建
     *
     * @param mnemonic 助记词列表
     * @return AccountDeriver 实例
     */
    public static AccountDeriver fromMnemonic(List<String> mnemonic) {
        return fromMnemonic(mnemonic, "");
    }

    /**
     * 从助记词和密码创建
     *
     * @param mnemonic   助记词列表
     * @param passphrase BIP-39 密码
     * @return AccountDeriver 实例
     */
    public static AccountDeriver fromMnemonic(List<String> mnemonic, String passphrase) {
        UnifiedHDWallet wallet = UnifiedHDWallet.fromMnemonic(mnemonic, passphrase);
        return new AccountDeriver(wallet);
    }

    /**
     * 从种子创建
     *
     * @param seed 64 字节种子
     * @return AccountDeriver 实例
     */
    public static AccountDeriver fromSeed(byte[] seed) {
        UnifiedHDWallet wallet = UnifiedHDWallet.fromSeed(seed);
        return new AccountDeriver(wallet);
    }

    // ==================== 核心派生方法 ====================

    /**
     * 为用户派生指定链的账户
     *
     * @param userId    用户标识符
     * @param chainType 链类型
     * @return 派生结果（包含地址和签名密钥）
     */
    public ChainDeriveResult deriveForUser(String userId, ChainType chainType) {
        return deriveForUser(userId, chainType, DeriveOptions.defaults());
    }

    /**
     * 为用户派生指定链的账户（带选项）
     *
     * @param userId    用户标识符
     * @param chainType 链类型
     * @param options   派生选项
     * @return 派生结果
     */
    public ChainDeriveResult deriveForUser(String userId, ChainType chainType, DeriveOptions options) {
        checkNotDestroyed();

        int accountIndex = userIdToAccountIndex(userId);
        String path = buildPath(chainType, accountIndex, options);
        DerivationScheme scheme = getScheme(chainType);

        DerivedKey derivedKey = hdWallet.derivePath(path, scheme);
        try {
            byte[] publicKey = getPublicKeyForChain(derivedKey, chainType);
            String address = encodeAddress(publicKey, chainType, options);
            SigningKey signingKey = derivedKey.toSigningKey();

            return new ChainDeriveResult(userId, accountIndex, path, chainType, address, signingKey);
        } finally {
            derivedKey.destroy();
        }
    }

    /**
     * 按路径派生
     *
     * @param path      派生路径
     * @param chainType 链类型
     * @return 派生结果
     */
    public ChainDeriveResult derivePath(String path, ChainType chainType) {
        return derivePath(path, chainType, DeriveOptions.defaults());
    }

    /**
     * 按路径派生（带选项）
     *
     * @param path      派生路径
     * @param chainType 链类型
     * @param options   派生选项
     * @return 派生结果
     */
    public ChainDeriveResult derivePath(String path, ChainType chainType, DeriveOptions options) {
        checkNotDestroyed();

        DerivationScheme scheme = getScheme(chainType);
        DerivedKey derivedKey = hdWallet.derivePath(path, scheme);
        try {
            byte[] publicKey = getPublicKeyForChain(derivedKey, chainType);
            String address = encodeAddress(publicKey, chainType, options);
            SigningKey signingKey = derivedKey.toSigningKey();

            return new ChainDeriveResult(null, -1, path, chainType, address, signingKey);
        } finally {
            derivedKey.destroy();
        }
    }

    // ==================== 批量派生 ====================

    /**
     * 批量派生账户
     *
     * @param chainType    链类型
     * @param startAccount 起始账户索引
     * @param count        派生数量
     * @return 派生结果列表
     */
    public List<ChainDeriveResult> deriveRange(ChainType chainType, int startAccount, int count) {
        return deriveRange(chainType, startAccount, count, DeriveOptions.defaults());
    }

    /**
     * 批量派生账户（带选项）
     *
     * @param chainType    链类型
     * @param startAccount 起始账户索引
     * @param count        派生数量
     * @param options      派生选项
     * @return 派生结果列表
     */
    public List<ChainDeriveResult> deriveRange(ChainType chainType, int startAccount, int count, DeriveOptions options) {
        checkNotDestroyed();

        List<ChainDeriveResult> results = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int accountIndex = startAccount + i;
            String path = buildPath(chainType, accountIndex, options);
            DerivationScheme scheme = getScheme(chainType);

            DerivedKey derivedKey = hdWallet.derivePath(path, scheme);
            try {
                byte[] publicKey = getPublicKeyForChain(derivedKey, chainType);
                String address = encodeAddress(publicKey, chainType, options);
                SigningKey signingKey = derivedKey.toSigningKey();

                results.add(new ChainDeriveResult(null, accountIndex, path, chainType, address, signingKey));
            } finally {
                derivedKey.destroy();
            }
        }
        return results;
    }

    // ==================== 只获取地址 ====================

    /**
     * 派生用户地址（不返回签名密钥）
     *
     * @param userId    用户标识符
     * @param chainType 链类型
     * @return 地址字符串
     */
    public String deriveAddress(String userId, ChainType chainType) {
        return deriveAddress(userId, chainType, DeriveOptions.defaults());
    }

    /**
     * 派生用户地址（带选项）
     *
     * @param userId    用户标识符
     * @param chainType 链类型
     * @param options   派生选项
     * @return 地址字符串
     */
    public String deriveAddress(String userId, ChainType chainType, DeriveOptions options) {
        checkNotDestroyed();

        int accountIndex = userIdToAccountIndex(userId);
        String path = buildPath(chainType, accountIndex, options);
        DerivationScheme scheme = getScheme(chainType);

        try (DerivedKey derivedKey = hdWallet.derivePath(path, scheme)) {
            byte[] publicKey = getPublicKeyForChain(derivedKey, chainType);
            return encodeAddress(publicKey, chainType, options);
        }
    }

    /**
     * 批量派生地址（不返回签名密钥）
     *
     * @param chainType    链类型
     * @param startAccount 起始账户索引
     * @param count        派生数量
     * @return 地址列表
     */
    public List<String> deriveAddresses(ChainType chainType, int startAccount, int count) {
        return deriveAddresses(chainType, startAccount, count, DeriveOptions.defaults());
    }

    /**
     * 批量派生地址（带选项）
     */
    public List<String> deriveAddresses(ChainType chainType, int startAccount, int count, DeriveOptions options) {
        checkNotDestroyed();

        List<String> addresses = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int accountIndex = startAccount + i;
            String path = buildPath(chainType, accountIndex, options);
            DerivationScheme scheme = getScheme(chainType);

            try (DerivedKey derivedKey = hdWallet.derivePath(path, scheme)) {
                byte[] publicKey = getPublicKeyForChain(derivedKey, chainType);
                addresses.add(encodeAddress(publicKey, chainType, options));
            }
        }
        return addresses;
    }

    // ==================== 静态工具方法 ====================

    /**
     * 从 userId 计算 account 索引
     *
     * 算法：SHA256(userId) -> 取前4字节 -> 转为无符号整数 -> % 2^31
     *
     * @param userId 用户标识符
     * @return 账户索引 (0 到 2^31-1)
     */
    public static int userIdToAccountIndex(String userId) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("userId cannot be null or empty");
        }

        byte[] hash = Sha256.hash(userId);
        long value = ByteBuffer.wrap(hash, 0, 4).getInt() & 0xFFFFFFFFL;
        return (int) (value % MAX_ACCOUNT_INDEX);
    }

    /**
     * 获取指定链的标准派生路径
     *
     * @param chainType    链类型
     * @param accountIndex 账户索引
     * @return 派生路径字符串
     */
    public static String getPathForChain(ChainType chainType, int accountIndex) {
        return getPathForChain(chainType, accountIndex, 0, 0);
    }

    /**
     * 获取指定链的派生路径
     *
     * @param chainType    链类型
     * @param accountIndex 账户索引
     * @param change       change 索引
     * @param addressIndex 地址索引
     * @return 派生路径字符串
     */
    public static String getPathForChain(ChainType chainType, int accountIndex, int change, int addressIndex) {
        int coinType = getCoinType(chainType);

        if (chainType.isEd25519()) {
            // Ed25519 链使用硬化的 address_index
            return String.format("m/44'/%d'/%d'/%d'", coinType, accountIndex, addressIndex);
        }

        return Bip44.getPath(coinType, accountIndex, change, addressIndex);
    }

    /**
     * 获取 BTC 特定地址类型的派生路径
     *
     * @param type         BTC 地址类型
     * @param accountIndex 账户索引
     * @return 派生路径字符串
     */
    public static String getPathForBtcType(BtcAddressType type, int accountIndex) {
        return getPathForBtcType(type, accountIndex, 0, 0);
    }

    /**
     * 获取 BTC 特定地址类型的派生路径
     *
     * @param type         BTC 地址类型
     * @param accountIndex 账户索引
     * @param change       change 索引
     * @param addressIndex 地址索引
     * @return 派生路径字符串
     */
    public static String getPathForBtcType(BtcAddressType type, int accountIndex, int change, int addressIndex) {
        int purpose = switch (type) {
            case P2PKH -> 44;
            case P2SH_P2WPKH -> 49;
            case P2WPKH, P2WSH -> 84;
            case P2TR -> 86;
        };
        return String.format("m/%d'/0'/%d'/%d/%d", purpose, accountIndex, change, addressIndex);
    }

    // ==================== 生命周期 ====================

    /**
     * 销毁派生器
     */
    public void destroy() {
        if (!destroyed) {
            hdWallet.destroy();
            destroyed = true;
        }
    }

    /**
     * 是否已销毁
     */
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroy();
    }

    // ==================== 内部方法 ====================

    private String buildPath(ChainType chainType, int accountIndex, DeriveOptions options) {
        if (chainType == ChainType.BTC) {
            return getPathForBtcType(
                    options.getBtcAddressType(),
                    accountIndex,
                    options.getChange(),
                    options.getAddressIndex()
            );
        }

        return getPathForChain(chainType, accountIndex, options.getChange(), options.getAddressIndex());
    }

    private DerivationScheme getScheme(ChainType chainType) {
        return chainType.isEd25519() ? DerivationScheme.SLIP10_ED25519 : DerivationScheme.BIP32_SECP256K1;
    }

    private byte[] getPublicKeyForChain(DerivedKey derivedKey, ChainType chainType) {
        AddressEncoder encoder = AddressEncoderRegistry.get(chainType);
        return switch (encoder.requiredFormat()) {
            case UNCOMPRESSED_65 -> derivedKey.getPublicKey(false);
            case COMPRESSED_33 -> derivedKey.getPublicKey(true);
            case ED25519_32 -> derivedKey.getPublicKey();
        };
    }

    private String encodeAddress(byte[] publicKey, ChainType chainType, DeriveOptions options) {
        AddressEncoder encoder = AddressEncoderRegistry.get(chainType);

        if (chainType == ChainType.BTC) {
            return encoder.encode(publicKey, new BtcAddressEncoder.BtcAddressOptions(
                    options.getBtcAddressType(),
                    options.getBtcNetwork()
            ));
        }

        return encoder.encode(publicKey);
    }

    private static int getCoinType(ChainType chainType) {
        return switch (chainType) {
            case EVM -> Bip44.COIN_TYPE_ETH;
            case BTC -> Bip44.COIN_TYPE_BTC;
            case TRON -> Bip44.COIN_TYPE_TRX;
            case SOL -> Bip44.COIN_TYPE_SOL;
            case APTOS -> 637;
            case COSMOS -> Bip44.COIN_TYPE_ATOM;
            case NEAR -> 397;
        };
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("AccountDeriver has been destroyed");
        }
    }

    @Override
    public String toString() {
        return "AccountDeriver{***REDACTED***}";
    }
}

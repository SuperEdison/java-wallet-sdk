package io.github.superedison.web3.crypto.wallet;

import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.kdf.Slip10;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 统一的链无关 HD 钱包
 *
 * 基于 BIP-32/39 和 SLIP-10 标准，支持：
 * - secp256k1 曲线（EVM, TRON, BTC 等）使用 BIP-32
 * - Ed25519 曲线（Solana, NEAR, Aptos 等）使用 SLIP-10
 *
 * 这个类是完全链无关的，只负责密钥派生。
 * 地址生成由各链的 AddressEncoder 负责。
 *
 * 使用示例：
 * <pre>{@code
 * // 从助记词创建
 * List<String> mnemonic = Bip39.generateMnemonic(12);
 * try (UnifiedHDWallet wallet = UnifiedHDWallet.fromMnemonic(mnemonic)) {
 *
 *     // 派生 EVM 密钥 (secp256k1)
 *     try (DerivedKey evmKey = wallet.derivePath("m/44'/60'/0'/0/0")) {
 *         SigningKey signer = evmKey.toSigningKey();
 *         byte[] publicKey = evmKey.getPublicKey(false); // 非压缩
 *     }
 *
 *     // 派生 Solana 密钥 (Ed25519)
 *     try (DerivedKey solKey = wallet.deriveEd25519("m/44'/501'/0'/0'")) {
 *         SigningKey signer = solKey.toSigningKey();
 *         byte[] publicKey = solKey.getPublicKey(); // 32 字节
 *     }
 * }
 * }</pre>
 */
public final class UnifiedHDWallet implements AutoCloseable {

    private final List<String> mnemonic;
    private final String passphrase;
    private final byte[] seed;
    private volatile boolean destroyed = false;

    // 懒加载的主密钥
    private volatile Bip32.ExtendedKey bip32MasterKey;
    private volatile Slip10.ExtendedKey slip10MasterKey;
    private final Object bip32Lock = new Object();
    private final Object slip10Lock = new Object();

    private UnifiedHDWallet(List<String> mnemonic, String passphrase, byte[] seed) {
        this.mnemonic = mnemonic != null ? List.copyOf(mnemonic) : null;
        this.passphrase = passphrase != null ? passphrase : "";
        this.seed = SecureBytes.copy(seed);
    }

    // ==================== 工厂方法 ====================

    /**
     * 从助记词创建 HD 钱包
     *
     * @param mnemonic 助记词列表（12, 15, 18, 21, 24 词）
     * @return UnifiedHDWallet 实例
     */
    public static UnifiedHDWallet fromMnemonic(List<String> mnemonic) {
        return fromMnemonic(mnemonic, "");
    }

    /**
     * 从助记词和密码创建 HD 钱包
     *
     * @param mnemonic   助记词列表
     * @param passphrase BIP-39 密码（可选）
     * @return UnifiedHDWallet 实例
     */
    public static UnifiedHDWallet fromMnemonic(List<String> mnemonic, String passphrase) {
        if (mnemonic == null || mnemonic.isEmpty()) {
            throw new IllegalArgumentException("Mnemonic cannot be null or empty");
        }
        if (!Bip39.validateMnemonic(mnemonic)) {
            throw new IllegalArgumentException("Invalid mnemonic");
        }

        String pass = passphrase != null ? passphrase : "";
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, pass);
        return new UnifiedHDWallet(mnemonic, pass, seed);
    }

    /**
     * 从种子创建 HD 钱包
     *
     * @param seed 64 字节种子
     * @return UnifiedHDWallet 实例
     */
    public static UnifiedHDWallet fromSeed(byte[] seed) {
        if (seed == null || seed.length != 64) {
            throw new IllegalArgumentException("Seed must be 64 bytes");
        }
        return new UnifiedHDWallet(null, null, seed);
    }

    // ==================== 核心派生方法 ====================

    /**
     * 按路径派生密钥（自动检测派生方案）
     *
     * 默认使用 BIP32_SECP256K1。如需 Ed25519，请使用 deriveEd25519() 或指定 scheme。
     *
     * @param path 派生路径，如 "m/44'/60'/0'/0/0"
     * @return DerivedKey 实例
     */
    public DerivedKey derivePath(String path) {
        return derivePath(path, DerivationScheme.BIP32_SECP256K1);
    }

    /**
     * 按路径和方案派生密钥
     *
     * @param path   派生路径
     * @param scheme 派生方案
     * @return DerivedKey 实例
     */
    public DerivedKey derivePath(String path, DerivationScheme scheme) {
        checkNotDestroyed();
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }

        return switch (scheme) {
            case BIP32_SECP256K1 -> deriveBip32(path);
            case SLIP10_ED25519 -> deriveSlip10(path);
        };
    }

    /**
     * 派生 secp256k1 密钥（BIP-32）
     *
     * 用于 EVM, TRON, BTC 等链
     *
     * @param path 派生路径
     * @return DerivedKey 实例
     */
    public DerivedKey deriveSecp256k1(String path) {
        return derivePath(path, DerivationScheme.BIP32_SECP256K1);
    }

    /**
     * 派生 Ed25519 密钥（SLIP-10）
     *
     * 用于 Solana, NEAR, Aptos 等链
     * 注意：SLIP-10 只支持硬化派生
     *
     * @param path 派生路径（所有索引必须是硬化的）
     * @return DerivedKey 实例
     */
    public DerivedKey deriveEd25519(String path) {
        return derivePath(path, DerivationScheme.SLIP10_ED25519);
    }

    // ==================== 批量派生 ====================

    /**
     * 批量派生密钥
     *
     * @param basePath 基础路径，最后一级将被替换为索引
     * @param start    起始索引
     * @param count    派生数量
     * @return DerivedKey 列表
     */
    public List<DerivedKey> deriveRange(String basePath, int start, int count) {
        return deriveRange(basePath, start, count, DerivationScheme.BIP32_SECP256K1);
    }

    /**
     * 批量派生密钥
     *
     * @param basePath 基础路径
     * @param start    起始索引
     * @param count    派生数量
     * @param scheme   派生方案
     * @return DerivedKey 列表
     */
    public List<DerivedKey> deriveRange(String basePath, int start, int count, DerivationScheme scheme) {
        checkNotDestroyed();
        if (start < 0 || count < 0) {
            throw new IllegalArgumentException("start and count must be non-negative");
        }

        List<DerivedKey> keys = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String path = buildIndexedPath(basePath, start + i);
            keys.add(derivePath(path, scheme));
        }
        return keys;
    }

    // ==================== 访问器 ====================

    /**
     * 获取助记词（如果有）
     *
     * @return 不可变的助记词列表，如果从种子创建则返回 null
     */
    public List<String> getMnemonic() {
        checkNotDestroyed();
        return mnemonic;
    }

    /**
     * 获取种子（返回副本）
     *
     * @return 64 字节种子副本
     */
    public byte[] getSeed() {
        checkNotDestroyed();
        return SecureBytes.copy(seed);
    }

    /**
     * 获取密码
     *
     * @return BIP-39 密码
     */
    public String getPassphrase() {
        checkNotDestroyed();
        return passphrase;
    }

    // ==================== 生命周期 ====================

    /**
     * 安全销毁钱包
     */
    public void destroy() {
        if (!destroyed) {
            SecureBytes.secureWipe(seed);

            synchronized (bip32Lock) {
                if (bip32MasterKey != null) {
                    bip32MasterKey.destroy();
                    bip32MasterKey = null;
                }
            }

            synchronized (slip10Lock) {
                if (slip10MasterKey != null) {
                    slip10MasterKey.destroy();
                    slip10MasterKey = null;
                }
            }

            destroyed = true;
        }
    }

    /**
     * 是否已销毁
     */
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * AutoCloseable 支持
     */
    @Override
    public void close() {
        destroy();
    }

    // ==================== 内部方法 ====================

    private DerivedKey deriveBip32(String path) {
        ensureBip32MasterKey();

        Bip32.ExtendedKey derived = Bip32.derivePath(bip32MasterKey, path);
        try {
            return new DerivedKey(
                    derived.privateKey(),
                    derived.chainCode(),
                    path,
                    DerivationScheme.BIP32_SECP256K1
            );
        } finally {
            derived.destroy();
        }
    }

    private DerivedKey deriveSlip10(String path) {
        ensureSlip10MasterKey();

        Slip10.ExtendedKey derived = Slip10.derivePath(slip10MasterKey, path);
        try {
            return new DerivedKey(
                    derived.getKey(),
                    derived.getChainCode(),
                    path,
                    DerivationScheme.SLIP10_ED25519
            );
        } finally {
            derived.destroy();
        }
    }

    private void ensureBip32MasterKey() {
        if (bip32MasterKey == null) {
            synchronized (bip32Lock) {
                if (bip32MasterKey == null) {
                    bip32MasterKey = Bip32.masterKeyFromSeed(seed);
                }
            }
        }
    }

    private void ensureSlip10MasterKey() {
        if (slip10MasterKey == null) {
            synchronized (slip10Lock) {
                if (slip10MasterKey == null) {
                    slip10MasterKey = Slip10.masterKeyFromSeed(seed, Slip10.Curve.ED25519);
                }
            }
        }
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("UnifiedHDWallet has been destroyed");
        }
    }

    /**
     * 构建带索引的路径
     * 将路径最后一级替换为指定索引
     */
    private String buildIndexedPath(String basePath, int index) {
        int lastSlash = basePath.lastIndexOf('/');
        if (lastSlash == -1) {
            return basePath + "/" + index;
        }
        return basePath.substring(0, lastSlash + 1) + index;
    }

    @Override
    public String toString() {
        return "UnifiedHDWallet{***REDACTED***}";
    }
}

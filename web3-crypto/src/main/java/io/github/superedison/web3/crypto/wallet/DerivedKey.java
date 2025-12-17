package io.github.superedison.web3.crypto.wallet;

import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.Arrays;

/**
 * HD 钱包派生密钥结果
 *
 * 链无关的密钥容器，包含：
 * - 私钥 (32 字节)
 * - 链码 (32 字节)
 * - 派生路径
 * - 派生方案 (BIP32/SLIP10)
 *
 * 使用示例：
 * <pre>{@code
 * try (DerivedKey key = hdWallet.derivePath("m/44'/60'/0'/0/0")) {
 *     SigningKey signer = key.toSigningKey();
 *     // 使用 signer 签名...
 * } // 自动销毁
 * }</pre>
 */
public final class DerivedKey implements AutoCloseable {

    private final byte[] privateKey;
    private final byte[] chainCode;
    private final String path;
    private final DerivationScheme scheme;
    private volatile boolean destroyed = false;

    /**
     * 创建派生密钥
     *
     * @param privateKey 32 字节私钥
     * @param chainCode  32 字节链码
     * @param path       派生路径
     * @param scheme     派生方案
     */
    public DerivedKey(byte[] privateKey, byte[] chainCode, String path, DerivationScheme scheme) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        if (chainCode == null || chainCode.length != 32) {
            throw new IllegalArgumentException("Chain code must be 32 bytes");
        }
        this.privateKey = SecureBytes.copy(privateKey);
        this.chainCode = SecureBytes.copy(chainCode);
        this.path = path != null ? path : "";
        this.scheme = scheme != null ? scheme : DerivationScheme.BIP32_SECP256K1;
    }

    /**
     * 创建 SigningKey
     *
     * 根据派生方案自动选择正确的签名器：
     * - BIP32_SECP256K1 → Secp256k1Signer
     * - SLIP10_ED25519 → Ed25519Signer
     *
     * 注意：调用者负责管理返回的 SigningKey 的生命周期
     *
     * @return SigningKey 实例
     */
    public SigningKey toSigningKey() {
        checkNotDestroyed();
        return switch (scheme) {
            case BIP32_SECP256K1 -> new Secp256k1Signer(privateKey);
            case SLIP10_ED25519 -> new Ed25519Signer(privateKey);
        };
    }

    /**
     * 获取私钥（返回副本）
     *
     * @return 32 字节私钥副本
     */
    public byte[] getPrivateKey() {
        checkNotDestroyed();
        return SecureBytes.copy(privateKey);
    }

    /**
     * 获取公钥
     *
     * 根据派生方案返回不同格式：
     * - BIP32_SECP256K1: 压缩公钥 (33 字节)
     * - SLIP10_ED25519: Ed25519 公钥 (32 字节)
     *
     * @return 公钥字节数组
     */
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return switch (scheme) {
            case BIP32_SECP256K1 -> Secp256k1Signer.derivePublicKey(privateKey, true);
            case SLIP10_ED25519 -> Ed25519Signer.derivePublicKey(privateKey);
        };
    }

    /**
     * 获取公钥（指定压缩格式，仅 secp256k1）
     *
     * @param compressed true=压缩(33字节), false=非压缩(65字节)
     * @return 公钥字节数组
     * @throws UnsupportedOperationException 如果是 Ed25519
     */
    public byte[] getPublicKey(boolean compressed) {
        checkNotDestroyed();
        return switch (scheme) {
            case BIP32_SECP256K1 -> Secp256k1Signer.derivePublicKey(privateKey, compressed);
            case SLIP10_ED25519 -> {
                if (!compressed) {
                    throw new UnsupportedOperationException("Ed25519 does not support uncompressed format");
                }
                yield Ed25519Signer.derivePublicKey(privateKey);
            }
        };
    }

    /**
     * 获取链码（返回副本）
     *
     * @return 32 字节链码副本
     */
    public byte[] getChainCode() {
        checkNotDestroyed();
        return SecureBytes.copy(chainCode);
    }

    /**
     * 获取派生路径
     *
     * @return 派生路径字符串，如 "m/44'/60'/0'/0/0"
     */
    public String getPath() {
        return path;
    }

    /**
     * 获取派生方案
     *
     * @return 派生方案枚举
     */
    public DerivationScheme getScheme() {
        return scheme;
    }

    /**
     * 安全销毁密钥材料
     */
    public void destroy() {
        if (!destroyed) {
            SecureBytes.secureWipe(privateKey);
            SecureBytes.wipe(chainCode);
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

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("DerivedKey has been destroyed");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DerivedKey that)) return false;
        checkNotDestroyed();
        that.checkNotDestroyed();
        return Arrays.equals(privateKey, that.privateKey) &&
               Arrays.equals(chainCode, that.chainCode) &&
               path.equals(that.path) &&
               scheme == that.scheme;
    }

    @Override
    public int hashCode() {
        checkNotDestroyed();
        int result = Arrays.hashCode(privateKey);
        result = 31 * result + Arrays.hashCode(chainCode);
        result = 31 * result + path.hashCode();
        result = 31 * result + scheme.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "DerivedKey{path='" + path + "', scheme=" + scheme + ", ***REDACTED***}";
    }
}

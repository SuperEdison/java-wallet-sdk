package io.github.superedison.web3.client.derive;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.hash.Sha256;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.kdf.Bip44;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * 账户派生工具类
 * 根据 userId 派生 EVM 地址
 *
 * 使用行业标准方案：
 * - 路径结构：m/44'/60'/ACCOUNT'/0/0
 * - 映射规则：ACCOUNT = hash(userId) % 2^31
 *
 * 适用于中心化钱包/交易所场景
 */
public final class AccountDeriver {

    /**
     * 最大账户索引 (2^31 - 1)，确保为正数且在 BIP-32 硬化范围内
     */
    private static final long MAX_ACCOUNT_INDEX = 0x7FFFFFFFL;

    private AccountDeriver() {}

    /**
     * 从 userId 派生 account 索引
     * 算法：SHA256(userId) -> 取前4字节 -> 转为无符号整数 -> % 2^31
     *
     * @param userId 用户标识符
     * @return account 索引 (0 到 2^31-1)
     */
    public static int userIdToAccountIndex(String userId) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("userId cannot be null or empty");
        }

        byte[] hash = Sha256.hash(userId);
        // 取前4字节，转为无符号整数
        long value = ByteBuffer.wrap(hash, 0, 4).getInt() & 0xFFFFFFFFL;
        // 取模确保在有效范围内
        return (int) (value % MAX_ACCOUNT_INDEX);
    }

    /**
     * 生成用户的 EVM 派生路径
     * 格式：m/44'/60'/ACCOUNT'/0/0
     *
     * @param userId 用户标识符
     * @return 派生路径字符串
     */
    public static String getEvmPathForUser(String userId) {
        int accountIndex = userIdToAccountIndex(userId);
        return Bip44.getPath(Bip44.COIN_TYPE_ETH, accountIndex, 0, 0);
    }

    /**
     * 从助记词派生用户的 EVM 地址
     *
     * @param mnemonic 主钱包助记词
     * @param passphrase BIP-39 密码（可选，传 null 或空字符串表示无密码）
     * @param userId 用户标识符
     * @return EVM 地址（带校验和）
     */
    public static String deriveEvmAddress(List<String> mnemonic, String passphrase, String userId) {
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, passphrase != null ? passphrase : "");
        try {
            return deriveEvmAddress(seed, userId);
        } finally {
            SecureBytes.secureWipe(seed);
        }
    }

    /**
     * 从主种子派生用户的 EVM 地址
     *
     * @param masterSeed 64字节主种子
     * @param userId 用户标识符
     * @return EVM 地址（带校验和）
     */
    public static String deriveEvmAddress(byte[] masterSeed, String userId) {
        String path = getEvmPathForUser(userId);
        Bip32.ExtendedKey key = Bip32.derivePath(masterSeed, path);
        try {
            byte[] publicKey = key.getUncompressedPublicKey();
            EvmAddress address = EvmAddress.fromPublicKey(publicKey);
            return address.toChecksumHex();
        } finally {
            key.destroy();
        }
    }

    /**
     * 从助记词派生用户的完整钱包信息
     *
     * @param mnemonic 主钱包助记词
     * @param passphrase BIP-39 密码
     * @param userId 用户标识符
     * @return 派生结果
     */
    public static DeriveResult deriveForUser(List<String> mnemonic, String passphrase, String userId) {
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, passphrase != null ? passphrase : "");
        try {
            return deriveForUser(seed, userId);
        } finally {
            SecureBytes.secureWipe(seed);
        }
    }

    /**
     * 从主种子派生用户的完整钱包信息
     *
     * @param masterSeed 64字节主种子
     * @param userId 用户标识符
     * @return 派生结果（使用后必须调用 close() 销毁私钥）
     */
    public static DeriveResult deriveForUser(byte[] masterSeed, String userId) {
        String path = getEvmPathForUser(userId);
        int accountIndex = userIdToAccountIndex(userId);
        Bip32.ExtendedKey key = Bip32.derivePath(masterSeed, path);

        byte[] publicKey = key.getUncompressedPublicKey();
        byte[] privateKeyBytes = SecureBytes.copy(key.privateKey());
        EvmAddress address = EvmAddress.fromPublicKey(publicKey);

        key.destroy();

        // 创建 SigningKey，私钥将由 SigningKey 管理
        SigningKey signingKey = new Secp256k1Signer(privateKeyBytes);
        // 立即擦除本地副本
        SecureBytes.secureWipe(privateKeyBytes);

        return new DeriveResult(
                userId,
                accountIndex,
                path,
                address.toChecksumHex(),
                signingKey
        );
    }

    /**
     * 派生结果
     * 实现 AutoCloseable 以支持 try-with-resources 自动销毁私钥
     *
     * 使用示例：
     * <pre>{@code
     * try (DeriveResult result = AccountDeriver.deriveForUser(seed, userId)) {
     *     result.signingKey().sign(hash);
     * } // 自动销毁私钥
     * }</pre>
     *
     * @param userId 用户ID
     * @param accountIndex 账户索引
     * @param path 派生路径
     * @param address EVM地址
     * @param signingKey 签名密钥（能力，不是数据）
     */
    public record DeriveResult(
            String userId,
            int accountIndex,
            String path,
            String address,
            SigningKey signingKey
    ) implements AutoCloseable {

        /**
         * 销毁签名密钥
         */
        @Override
        public void close() {
            if (signingKey != null) {
                signingKey.destroy();
            }
        }

        /**
         * 是否已销毁
         */
        public boolean isDestroyed() {
            return signingKey == null || signingKey.isDestroyed();
        }
    }
}

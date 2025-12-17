package io.github.superedison.web3.chain.solana.address;

import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.wallet.Address;

import java.util.Arrays;

/**
 * Solana 地址
 * 32 字节（Ed25519 公钥），Base58 编码
 *
 * Solana 地址直接使用 Ed25519 公钥，没有额外的哈希或前缀
 */
public final class SolanaAddress implements Address {

    /**
     * Solana 地址长度（字节）
     */
    public static final int LENGTH = 32;

    private final byte[] bytes;

    private SolanaAddress(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * 从 32 字节创建地址
     * @param bytes 32 字节地址（Ed25519 公钥）
     * @return SolanaAddress 实例
     * @throws AddressException 如果字节长度不正确
     */
    public static SolanaAddress fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new AddressException("Solana address must be 32 bytes, got: " +
                (bytes == null ? "null" : bytes.length));
        }
        return new SolanaAddress(Arrays.copyOf(bytes, LENGTH));
    }

    /**
     * 从 Base58 编码的地址字符串解析
     * @param base58 Base58 编码的地址
     * @return SolanaAddress 实例
     * @throws AddressException 如果地址格式无效
     */
    public static SolanaAddress fromBase58(String base58) {
        if (base58 == null || base58.isEmpty()) {
            throw AddressException.invalidFormat(base58);
        }
        try {
            byte[] decoded = Base58.decode(base58);
            return fromBytes(decoded);
        } catch (IllegalArgumentException e) {
            throw new AddressException("Invalid Base58 address: " + base58, e);
        }
    }

    /**
     * 从 Ed25519 公钥创建地址
     * Solana 地址就是公钥本身
     *
     * @param publicKey 32 字节 Ed25519 公钥
     * @return SolanaAddress 实例
     * @throws AddressException 如果公钥长度不正确
     */
    public static SolanaAddress fromPublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != LENGTH) {
            throw new AddressException("Ed25519 public key must be 32 bytes, got: " +
                (publicKey == null ? "null" : publicKey.length));
        }
        return new SolanaAddress(Arrays.copyOf(publicKey, LENGTH));
    }

    /**
     * 验证地址格式
     * @param address Base58 编码的地址字符串
     * @return 如果格式有效返回 true
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // Solana 地址通常是 32-44 个字符
        if (address.length() < 32 || address.length() > 44) {
            return false;
        }
        try {
            byte[] decoded = Base58.decode(address);
            return decoded.length == LENGTH;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String toBase58() {
        return Base58.encode(bytes);
    }

    @Override
    public byte[] toBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public boolean isValid() {
        return true;
    }

    /**
     * 获取十六进制地址
     * @return 64 字符十六进制字符串
     */
    public String toHex() {
        return bytesToHex(bytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SolanaAddress that)) return false;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toBase58();
    }
}
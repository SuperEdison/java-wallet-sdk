package io.github.superedison.web3.chain.tron.address;

import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.crypto.hash.Keccak256;

import java.util.Arrays;

/**
 * TRON 地址
 * 21 字节 (0x41 前缀 + 20 字节)，Base58Check 编码
 * 主网地址以 T 开头
 */
public final class TronAddress implements Address {

    /**
     * TRON 主网地址前缀
     */
    public static final byte MAINNET_PREFIX = 0x41;

    /**
     * 地址总长度（含前缀）
     */
    private static final int LENGTH = 21;

    /**
     * 地址主体长度（不含前缀）
     */
    private static final int BODY_LENGTH = 20;

    private final byte[] bytes;

    private TronAddress(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * 从 21 字节创建地址
     * @param bytes 21 字节地址（包含 0x41 前缀）
     * @return TronAddress 实例
     * @throws AddressException 如果字节长度不正确或前缀无效
     */
    public static TronAddress fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new AddressException("TRON address must be 21 bytes");
        }
        if (bytes[0] != MAINNET_PREFIX) {
            throw new AddressException("Invalid TRON address prefix: expected 0x41");
        }
        return new TronAddress(Arrays.copyOf(bytes, LENGTH));
    }

    /**
     * 从 Base58Check 编码的地址字符串解析
     * @param base58 Base58Check 编码的地址（以 T 开头）
     * @return TronAddress 实例
     * @throws AddressException 如果地址格式无效
     */
    public static TronAddress fromBase58(String base58) {
        if (base58 == null || base58.isEmpty()) {
            throw AddressException.invalidFormat(base58);
        }
        try {
            byte[] decoded = Base58Check.decodeChecked(base58);
            return fromBytes(decoded);
        } catch (IllegalArgumentException e) {
            throw AddressException.invalidFormat(base58);
        }
    }

    /**
     * 从十六进制字符串解析
     * @param hex 十六进制地址（42 字符，以 41 开头）
     * @return TronAddress 实例
     * @throws AddressException 如果格式无效
     */
    public static TronAddress fromHex(String hex) {
        String clean = normalize(hex);
        if (clean == null) {
            throw AddressException.invalidFormat(hex);
        }
        return new TronAddress(hexToBytes(clean));
    }

    /**
     * 从公钥派生地址
     * @param publicKey 65 字节（04 前缀）或 64 字节公钥
     * @return TronAddress 实例
     * @throws AddressException 如果公钥格式无效
     */
    public static TronAddress fromPublicKey(byte[] publicKey) {
        byte[] key = publicKey;
        if (publicKey.length == 65 && publicKey[0] == 0x04) {
            key = Arrays.copyOfRange(publicKey, 1, 65);
        }
        if (key.length != 64) {
            throw new AddressException("Invalid public key length");
        }
        // Keccak256 哈希，取后 20 字节
        byte[] hash = Keccak256.hash(key);
        byte[] addressBody = Arrays.copyOfRange(hash, 12, 32);

        // 添加 0x41 前缀
        byte[] address = new byte[LENGTH];
        address[0] = MAINNET_PREFIX;
        System.arraycopy(addressBody, 0, address, 1, BODY_LENGTH);

        return new TronAddress(address);
    }

    /**
     * 验证地址格式
     * @param address 地址字符串（Base58Check 或十六进制）
     * @return 如果格式有效返回 true
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // 检查是否为十六进制格式
        if (address.startsWith("41") || address.startsWith("0x41")) {
            return normalize(address) != null;
        }
        // 检查 Base58Check 格式
        if (!address.startsWith("T")) {
            return false;
        }
        try {
            byte[] decoded = Base58Check.decodeChecked(address);
            return decoded.length == LENGTH && decoded[0] == MAINNET_PREFIX;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String toBase58() {
        return Base58Check.encodeChecked(bytes);
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
     * 获取十六进制地址（42 字符）
     * @return 十六进制地址字符串
     */
    public String toHex() {
        return bytesToHex(bytes);
    }

    /**
     * 获取带 0x 前缀的十六进制地址
     * @return 0x 前缀的十六进制地址字符串
     */
    public String toHexWith0x() {
        return "0x" + bytesToHex(bytes);
    }

    private static String normalize(String address) {
        if (address == null || address.isEmpty()) {
            return null;
        }
        String hex = address.startsWith("0x") || address.startsWith("0X")
                ? address.substring(2) : address;
        if (hex.length() != 42 || !hex.matches("[0-9a-fA-F]+")) {
            return null;
        }
        if (!hex.toLowerCase().startsWith("41")) {
            return null;
        }
        return hex.toLowerCase();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
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
        if (!(o instanceof TronAddress that)) return false;
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

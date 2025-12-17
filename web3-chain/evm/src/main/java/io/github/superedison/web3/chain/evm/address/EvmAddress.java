package io.github.superedison.web3.chain.evm.address;

import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.crypto.hash.Keccak256;

import java.util.Arrays;

/**
 * EVM 地址
 * 20 字节，0x 前缀，EIP-55 校验和
 */
public final class EvmAddress implements Address {

    private static final int LENGTH = 20;
    private final byte[] bytes;

    private EvmAddress(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * 从字节创建
     */
    public static EvmAddress fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new AddressException("EVM address must be 20 bytes");
        }
        return new EvmAddress(Arrays.copyOf(bytes, LENGTH));
    }

    /**
     * 从十六进制字符串解析
     */
    public static EvmAddress fromHex(String hex) {
        String clean = normalize(hex);
        if (clean == null) {
            throw AddressException.invalidFormat(hex);
        }
        return new EvmAddress(hexToBytes(clean));
    }

    /**
     * 从公钥派生
     * @param publicKey 65 字节（04 前缀）或 64 字节公钥
     */
    public static EvmAddress fromPublicKey(byte[] publicKey) {
        byte[] key = publicKey;
        if (publicKey.length == 65 && publicKey[0] == 0x04) {
            key = Arrays.copyOfRange(publicKey, 1, 65);
        }
        if (key.length != 64) {
            throw new AddressException("Invalid public key length");
        }
        byte[] hash = Keccak256.hash(key);
        return new EvmAddress(Arrays.copyOfRange(hash, 12, 32));
    }

    /**
     * 验证地址格式
     */
    public static boolean isValid(String address) {
        return normalize(address) != null;
    }

    @Override
    public String toBase58() {
        return toChecksumHex();
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
     * 获取小写十六进制（带 0x）
     */
    public String toHex() {
        return "0x" + bytesToHex(bytes);
    }

    /**
     * 获取 EIP-55 校验和地址
     */
    public String toChecksumHex() {
        return Eip55Checksum.apply(bytesToHex(bytes));
    }

    private static String normalize(String address) {
        if (address == null || address.isEmpty()) {
            return null;
        }
        String hex = address.startsWith("0x") || address.startsWith("0X")
                ? address.substring(2) : address;
        if (hex.length() != 40 || !hex.matches("[0-9a-fA-F]+")) {
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
        if (!(o instanceof EvmAddress that)) return false;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toChecksumHex();
    }
}
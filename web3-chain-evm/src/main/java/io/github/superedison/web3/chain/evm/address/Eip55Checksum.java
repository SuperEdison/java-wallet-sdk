package io.github.superedison.web3.chain.evm.address;

import io.github.superedison.web3.crypto.hash.Keccak256;

/**
 * EIP-55 地址校验和
 */
public final class Eip55Checksum {

    private Eip55Checksum() {}

    /**
     * 应用 EIP-55 校验和
     * @param address 40 字符十六进制地址（不含 0x）
     * @return 带校验和的地址（含 0x）
     */
    public static String apply(String address) {
        String lower = address.toLowerCase();
        byte[] hash = Keccak256.hash(lower.getBytes());
        StringBuilder sb = new StringBuilder("0x");

        for (int i = 0; i < 40; i++) {
            char c = lower.charAt(i);
            if (c >= 'a' && c <= 'f') {
                int hashByte = hash[i / 2] & 0xFF;
                int nibble = (i % 2 == 0) ? (hashByte >> 4) : (hashByte & 0x0F);
                if (nibble >= 8) {
                    c = Character.toUpperCase(c);
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * 验证 EIP-55 校验和
     */
    public static boolean verify(String address) {
        if (address == null || address.length() != 42 || !address.startsWith("0x")) {
            return false;
        }
        String hex = address.substring(2);
        if (!hex.matches("[0-9a-fA-F]+")) {
            return false;
        }
        String checksummed = apply(hex);
        return checksummed.equals(address);
    }
}
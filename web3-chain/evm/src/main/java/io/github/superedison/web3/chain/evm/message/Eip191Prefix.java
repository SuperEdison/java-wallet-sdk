package io.github.superedison.web3.chain.evm.message;

import io.github.superedison.web3.crypto.hash.Keccak256;

import java.nio.charset.StandardCharsets;

/**
 * EIP-191 消息前缀
 * personal_sign 格式
 */
public final class Eip191Prefix {

    private static final String PREFIX = "\u0019Ethereum Signed Message:\n";

    private Eip191Prefix() {}

    /**
     * 计算 EIP-191 消息哈希
     * hash = keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
     */
    public static byte[] hash(byte[] message) {
        byte[] prefix = (PREFIX + message.length).getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, combined, 0, prefix.length);
        System.arraycopy(message, 0, combined, prefix.length, message.length);
        return Keccak256.hash(combined);
    }

    /**
     * 计算字符串消息的 EIP-191 哈希
     */
    public static byte[] hash(String message) {
        return hash(message.getBytes(StandardCharsets.UTF_8));
    }
}
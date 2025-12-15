package io.github.superedison.web3.crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 哈希算法
 * 用于比特币和 BIP39
 */
public final class Sha256 {

    private Sha256() {}

    /**
     * 计算 SHA-256 哈希
     * @param input 输入数据
     * @return 32字节哈希值
     */
    public static byte[] hash(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 计算字符串的 SHA-256 哈希
     * @param input 输入字符串
     * @return 32字节哈希值
     */
    public static byte[] hash(String input) {
        return hash(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 计算双重 SHA-256 哈希 (SHA256(SHA256(input)))
     * 用于比特币
     * @param input 输入数据
     * @return 32字节哈希值
     */
    public static byte[] doubleHash(byte[] input) {
        return hash(hash(input));
    }

    /**
     * 计算多个数据块的 SHA-256 哈希
     * @param inputs 输入数据块
     * @return 32字节哈希值
     */
    public static byte[] hash(byte[]... inputs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] input : inputs) {
                digest.update(input);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 计算哈希并返回十六进制字符串
     * @param input 输入数据
     * @return 十六进制哈希字符串
     */
    public static String hashHex(byte[] input) {
        return bytesToHex(hash(input));
    }

    /**
     * 计算 HMAC-SHA256
     * @param key 密钥
     * @param data 数据
     * @return HMAC值
     */
    public static byte[] hmac(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
package io.github.superedison.web3.crypto.hash;

import org.bouncycastle.jcajce.provider.digest.Keccak;

/**
 * Keccak-256 哈希算法
 * 用于以太坊地址生成和消息签名
 */
public final class Keccak256 {

    private Keccak256() {}

    /**
     * 计算 Keccak-256 哈希
     * @param input 输入数据
     * @return 32字节哈希值
     */
    public static byte[] hash(byte[] input) {
        Keccak.Digest256 digest = new Keccak.Digest256();
        return digest.digest(input);
    }

    /**
     * 计算字符串的 Keccak-256 哈希
     * @param input 输入字符串
     * @return 32字节哈希值
     */
    public static byte[] hash(String input) {
        return hash(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 计算多个数据块的 Keccak-256 哈希
     * @param inputs 输入数据块
     * @return 32字节哈希值
     */
    public static byte[] hash(byte[]... inputs) {
        Keccak.Digest256 digest = new Keccak.Digest256();
        for (byte[] input : inputs) {
            digest.update(input);
        }
        return digest.digest();
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
     * 计算哈希并返回带0x前缀的十六进制字符串
     * @param input 输入数据
     * @return 带0x前缀的十六进制哈希字符串
     */
    public static String hashHexWithPrefix(byte[] input) {
        return "0x" + hashHex(input);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
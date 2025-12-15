package io.github.superedison.web3.crypto.hash;

import org.bouncycastle.crypto.digests.Blake2bDigest;

/**
 * Blake2b 哈希算法
 * 用于 Solana, NEAR, Algorand 等链
 */
public final class Blake2b {

    private Blake2b() {}

    /**
     * 计算 Blake2b-256 哈希
     * @param input 输入数据
     * @return 32字节哈希值
     */
    public static byte[] hash256(byte[] input) {
        return hash(input, 32);
    }

    /**
     * 计算 Blake2b-512 哈希
     * @param input 输入数据
     * @return 64字节哈希值
     */
    public static byte[] hash512(byte[] input) {
        return hash(input, 64);
    }

    /**
     * 计算指定长度的 Blake2b 哈希
     * @param input 输入数据
     * @param outputLength 输出长度（字节）
     * @return 哈希值
     */
    public static byte[] hash(byte[] input, int outputLength) {
        Blake2bDigest digest = new Blake2bDigest(outputLength * 8);
        digest.update(input, 0, input.length);
        byte[] output = new byte[outputLength];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * 计算带密钥的 Blake2b 哈希（MAC）
     * @param key 密钥
     * @param input 输入数据
     * @param outputLength 输出长度
     * @return 哈希值
     */
    public static byte[] hashWithKey(byte[] key, byte[] input, int outputLength) {
        Blake2bDigest digest = new Blake2bDigest(key, outputLength, null, null);
        digest.update(input, 0, input.length);
        byte[] output = new byte[outputLength];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * 计算哈希并返回十六进制字符串
     * @param input 输入数据
     * @return 十六进制哈希字符串
     */
    public static String hash256Hex(byte[] input) {
        return bytesToHex(hash256(input));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
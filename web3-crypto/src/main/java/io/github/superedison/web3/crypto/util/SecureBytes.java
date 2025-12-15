package io.github.superedison.web3.crypto.util;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 安全字节数组工具类
 * 提供安全的字节数组操作，包括擦除敏感数据
 */
public final class SecureBytes {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureBytes() {}

    /**
     * 安全擦除字节数组（填充0）
     * @param bytes 待擦除的字节数组
     */
    public static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * 安全擦除字节数组（填充随机数后再填充0）
     * @param bytes 待擦除的字节数组
     */
    public static void secureWipe(byte[] bytes) {
        if (bytes != null) {
            // 先用随机数覆盖
            SECURE_RANDOM.nextBytes(bytes);
            // 再填充0
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * 安全擦除多个字节数组
     * @param arrays 待擦除的字节数组
     */
    public static void wipeAll(byte[]... arrays) {
        for (byte[] array : arrays) {
            wipe(array);
        }
    }

    /**
     * 安全复制字节数组
     * @param source 源数组
     * @return 复制的新数组
     */
    public static byte[] copy(byte[] source) {
        if (source == null) {
            return null;
        }
        return Arrays.copyOf(source, source.length);
    }

    /**
     * 安全复制指定范围
     * @param source 源数组
     * @param from 起始位置
     * @param to 结束位置
     * @return 复制的新数组
     */
    public static byte[] copyRange(byte[] source, int from, int to) {
        if (source == null) {
            return null;
        }
        return Arrays.copyOfRange(source, from, to);
    }

    /**
     * 生成安全随机字节
     * @param length 长度
     * @return 随机字节数组
     */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * 常量时间比较（防止时序攻击）
     * @param a 字节数组a
     * @param b 字节数组b
     * @return 如果相等返回 true
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * 连接多个字节数组
     * @param arrays 字节数组
     * @return 连接后的数组
     */
    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        byte[] result = new byte[totalLength];
        int pos = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, pos, array.length);
                pos += array.length;
            }
        }
        return result;
    }

    /**
     * 左填充到指定长度
     * 如果输入长度超过目标长度，截取最后 length 字节（去掉前导字节）
     * @param bytes 原数组
     * @param length 目标长度
     * @return 填充/截断后的数组
     */
    public static byte[] padLeft(byte[] bytes, int length) {
        if (bytes == null) {
            return new byte[length];
        }
        if (bytes.length == length) {
            return copy(bytes);
        }
        if (bytes.length > length) {
            // 截取最后 length 字节（用于 BigInteger 带符号位的情况）
            byte[] truncated = new byte[length];
            System.arraycopy(bytes, bytes.length - length, truncated, 0, length);
            return truncated;
        }
        byte[] padded = new byte[length];
        System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
        return padded;
    }

    /**
     * 移除前导零
     * @param bytes 字节数组
     * @return 去除前导零的数组
     */
    public static byte[] stripLeadingZeros(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new byte[0];
        }
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) {
            start++;
        }
        return Arrays.copyOfRange(bytes, start, bytes.length);
    }
}
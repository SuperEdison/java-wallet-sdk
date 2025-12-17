package io.github.superedison.web3.chain.solana.address;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58 编码/解码
 * 用于 Solana 地址的 Base58 格式（不含校验和）
 */
public final class Base58 {

    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    private Base58() {}

    /**
     * Base58 编码
     * @param input 输入字节
     * @return Base58 编码字符串
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }

        // 计算前导零的数量
        int leadingZeros = 0;
        while (leadingZeros < input.length && input[leadingZeros] == 0) {
            leadingZeros++;
        }

        // 转换为 Base58
        byte[] temp = Arrays.copyOf(input, input.length);
        char[] encoded = new char[temp.length * 2];
        int outputStart = encoded.length;

        int start = leadingZeros;
        while (start < temp.length) {
            int remainder = divmod(temp, start, 256, 58);
            if (temp[start] == 0) {
                start++;
            }
            encoded[--outputStart] = ALPHABET[remainder];
        }

        // 保留前导零
        while (outputStart < encoded.length && encoded[outputStart] == ALPHABET[0]) {
            outputStart++;
        }
        while (leadingZeros-- > 0) {
            encoded[--outputStart] = ALPHABET[0];
        }

        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Base58 解码
     * @param input Base58 编码字符串
     * @return 解码后的字节数组
     * @throws IllegalArgumentException 如果输入包含无效字符
     */
    public static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }

        // 计算前导 '1' 的数量（表示前导零）
        int leadingOnes = 0;
        while (leadingOnes < input.length() && input.charAt(leadingOnes) == ALPHABET[0]) {
            leadingOnes++;
        }

        // 使用 BigInteger 进行转换
        BigInteger bi = BigInteger.ZERO;
        for (int i = leadingOnes; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid Base58 character: " + c);
            }
            bi = bi.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }

        // 处理只有前导 1 的情况
        if (bi.equals(BigInteger.ZERO)) {
            return new byte[leadingOnes];
        }

        byte[] bytes = bi.toByteArray();

        // 去除前导零（BigInteger 可能添加符号位）
        int stripZeros = 0;
        while (stripZeros < bytes.length && bytes[stripZeros] == 0) {
            stripZeros++;
        }

        // 构建结果：前导零 + 实际数据
        byte[] result = new byte[leadingOnes + bytes.length - stripZeros];
        System.arraycopy(bytes, stripZeros, result, leadingOnes, bytes.length - stripZeros);

        return result;
    }

    /**
     * 除法取模，用于进制转换
     */
    private static int divmod(byte[] number, int start, int base, int divisor) {
        int remainder = 0;
        for (int i = start; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return remainder;
    }
}
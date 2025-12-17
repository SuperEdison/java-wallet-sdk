package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.crypto.hash.Sha256;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58Check 编码/解码
 * 用于 Bitcoin Legacy 和 P2SH 地址
 */
public final class Base58Check {

    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];
    private static final int CHECKSUM_LENGTH = 4;

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    private Base58Check() {}

    /**
     * Base58 编码
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }

        int leadingZeros = 0;
        while (leadingZeros < input.length && input[leadingZeros] == 0) {
            leadingZeros++;
        }

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
     */
    public static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }

        int leadingOnes = 0;
        while (leadingOnes < input.length() && input.charAt(leadingOnes) == ALPHABET[0]) {
            leadingOnes++;
        }

        BigInteger bi = BigInteger.ZERO;
        for (int i = leadingOnes; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid Base58 character: " + c);
            }
            bi = bi.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }

        if (bi.equals(BigInteger.ZERO)) {
            return new byte[leadingOnes];
        }

        byte[] bytes = bi.toByteArray();

        int stripZeros = 0;
        while (stripZeros < bytes.length && bytes[stripZeros] == 0) {
            stripZeros++;
        }

        byte[] result = new byte[leadingOnes + bytes.length - stripZeros];
        System.arraycopy(bytes, stripZeros, result, leadingOnes, bytes.length - stripZeros);

        return result;
    }

    /**
     * Base58Check 编码（带版本前缀和校验和）
     */
    public static String encodeChecked(byte version, byte[] payload) {
        byte[] data = new byte[1 + payload.length + CHECKSUM_LENGTH];
        data[0] = version;
        System.arraycopy(payload, 0, data, 1, payload.length);
        byte[] checksum = computeChecksum(data, 0, 1 + payload.length);
        System.arraycopy(checksum, 0, data, 1 + payload.length, CHECKSUM_LENGTH);
        return encode(data);
    }

    /**
     * Base58Check 解码（验证校验和，返回不含版本前缀的数据）
     */
    public static DecodedAddress decodeChecked(String input) {
        byte[] data = decode(input);
        if (data.length < 1 + CHECKSUM_LENGTH) {
            throw new IllegalArgumentException("Input too short for Base58Check");
        }

        byte[] payload = Arrays.copyOfRange(data, 0, data.length - CHECKSUM_LENGTH);
        byte[] checksum = Arrays.copyOfRange(data, data.length - CHECKSUM_LENGTH, data.length);
        byte[] expectedChecksum = computeChecksum(payload, 0, payload.length);

        if (!Arrays.equals(checksum, expectedChecksum)) {
            throw new IllegalArgumentException("Invalid Base58Check checksum");
        }

        byte version = payload[0];
        byte[] hash = Arrays.copyOfRange(payload, 1, payload.length);

        return new DecodedAddress(version, hash);
    }

    /**
     * 计算校验和（SHA256 双哈希的前 4 字节）
     */
    private static byte[] computeChecksum(byte[] data, int offset, int length) {
        byte[] toHash = Arrays.copyOfRange(data, offset, offset + length);
        byte[] hash = Sha256.doubleHash(toHash);
        return Arrays.copyOfRange(hash, 0, CHECKSUM_LENGTH);
    }

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

    /**
     * 解码后的地址数据
     */
    public record DecodedAddress(byte version, byte[] hash) {
        public DecodedAddress {
            hash = Arrays.copyOf(hash, hash.length);
        }

        public byte[] hash() {
            return Arrays.copyOf(hash, hash.length);
        }
    }
}

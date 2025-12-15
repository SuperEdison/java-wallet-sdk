package io.github.superedison.web3.chain.evm.rlp;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;

/**
 * RLP 编码器
 * 只实现 EVM 交易签名所需的最小集合
 */
public final class RlpEncoder {

    private RlpEncoder() {}

    /**
     * 编码字节数组
     */
    public static byte[] encodeBytes(byte[] value) {
        // 空数组 → 0x80
        if (value == null || value.length == 0) {
            return new byte[]{(byte) 0x80};
        }

        // 单字节且 < 0x80 → 直接返回
        if (value.length == 1 && (value[0] & 0xFF) < 0x80) {
            return value;
        }

        // 长度 ≤ 55 → 0x80 + len + bytes
        if (value.length <= 55) {
            byte[] result = new byte[1 + value.length];
            result[0] = (byte) (0x80 + value.length);
            System.arraycopy(value, 0, result, 1, value.length);
            return result;
        }

        // 长度 > 55 → 0xb7 + len(len) + len + bytes
        byte[] lenBytes = toMinimalBytes(value.length);
        byte[] result = new byte[1 + lenBytes.length + value.length];
        result[0] = (byte) (0xb7 + lenBytes.length);
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(value, 0, result, 1 + lenBytes.length, value.length);
        return result;
    }

    /**
     * 编码 BigInteger
     * 注意：0 编码为空字节 (0x80)
     */
    public static byte[] encodeBigInteger(BigInteger value) {
        if (value == null || value.equals(BigInteger.ZERO)) {
            return encodeBytes(new byte[0]);
        }

        // 转为最短无符号 big-endian
        byte[] bytes = value.toByteArray();

        // 去掉前导 0x00（BigInteger 带符号位）
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        return encodeBytes(bytes);
    }

    /**
     * 编码 long
     */
    public static byte[] encodeLong(long value) {
        if (value == 0) {
            return encodeBytes(new byte[0]);
        }
        return encodeBigInteger(BigInteger.valueOf(value));
    }

    /**
     * 编码列表
     * @param encodedElements 已编码的元素列表
     */
    public static byte[] encodeList(List<byte[]> encodedElements) {
        // 合并所有元素
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (byte[] element : encodedElements) {
            bos.writeBytes(element);
        }
        byte[] payload = bos.toByteArray();

        // 总长度 ≤ 55 → 0xc0 + len + payload
        if (payload.length <= 55) {
            byte[] result = new byte[1 + payload.length];
            result[0] = (byte) (0xc0 + payload.length);
            System.arraycopy(payload, 0, result, 1, payload.length);
            return result;
        }

        // 总长度 > 55 → 0xf7 + len(len) + len + payload
        byte[] lenBytes = toMinimalBytes(payload.length);
        byte[] result = new byte[1 + lenBytes.length + payload.length];
        result[0] = (byte) (0xf7 + lenBytes.length);
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(payload, 0, result, 1 + lenBytes.length, payload.length);
        return result;
    }

    /**
     * 编码列表（可变参数版本）
     */
    public static byte[] encodeList(byte[]... encodedElements) {
        return encodeList(List.of(encodedElements));
    }

    /**
     * 编码地址（20 字节）
     */
    public static byte[] encodeAddress(byte[] address) {
        if (address == null || address.length == 0) {
            return encodeBytes(new byte[0]);
        }
        if (address.length != 20) {
            throw new IllegalArgumentException("Address must be 20 bytes");
        }
        return encodeBytes(address);
    }

    /**
     * 将 int 转为最短字节表示
     */
    private static byte[] toMinimalBytes(int value) {
        if (value == 0) {
            return new byte[0];
        }

        // 计算需要多少字节
        int numBytes = 0;
        int temp = value;
        while (temp != 0) {
            numBytes++;
            temp >>>= 8;
        }

        byte[] bytes = new byte[numBytes];
        for (int i = numBytes - 1; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return bytes;
    }
}
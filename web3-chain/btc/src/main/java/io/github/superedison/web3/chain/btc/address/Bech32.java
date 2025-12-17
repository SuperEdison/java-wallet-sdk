package io.github.superedison.web3.chain.btc.address;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

/**
 * Bech32 和 Bech32m 编码/解码
 * 用于 Bitcoin SegWit 和 Taproot 地址
 *
 * BIP-173: Bech32 (SegWit v0)
 * BIP-350: Bech32m (SegWit v1+, Taproot)
 */
public final class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] CHARSET_REV = new int[128];

    // Bech32 常量
    private static final int BECH32_CONST = 1;
    // Bech32m 常量
    private static final int BECH32M_CONST = 0x2bc830a3;

    static {
        Arrays.fill(CHARSET_REV, -1);
        for (int i = 0; i < CHARSET.length(); i++) {
            CHARSET_REV[CHARSET.charAt(i)] = i;
        }
    }

    private Bech32() {}

    /**
     * Bech32 编码类型
     */
    public enum Encoding {
        BECH32,
        BECH32M
    }

    /**
     * Bech32 编码（SegWit v0）
     */
    public static String encode(String hrp, byte[] data) {
        return encodeInternal(hrp, data, Encoding.BECH32);
    }

    /**
     * Bech32m 编码（Taproot / SegWit v1+）
     */
    public static String encodeBech32m(String hrp, byte[] data) {
        return encodeInternal(hrp, data, Encoding.BECH32M);
    }

    /**
     * 编码 SegWit 地址
     */
    public static String encodeSegWitAddress(String hrp, int witnessVersion, byte[] witnessProgram) {
        byte[] converted = convertBits(witnessProgram, 8, 5, true);
        byte[] data = new byte[1 + converted.length];
        data[0] = (byte) witnessVersion;
        System.arraycopy(converted, 0, data, 1, converted.length);

        Encoding encoding = witnessVersion == 0 ? Encoding.BECH32 : Encoding.BECH32M;
        return encodeInternal(hrp, data, encoding);
    }

    /**
     * 解码 Bech32/Bech32m
     */
    public static DecodedBech32 decode(String str) {
        String lower = str.toLowerCase(Locale.ROOT);
        String upper = str.toUpperCase(Locale.ROOT);

        if (!str.equals(lower) && !str.equals(upper)) {
            throw new IllegalArgumentException("Mixed case in Bech32 string");
        }

        str = lower;

        int pos = str.lastIndexOf('1');
        if (pos < 1 || pos + 7 > str.length() || str.length() > 90) {
            throw new IllegalArgumentException("Invalid Bech32 format");
        }

        String hrp = str.substring(0, pos);
        String dataStr = str.substring(pos + 1);

        byte[] data = new byte[dataStr.length()];
        for (int i = 0; i < dataStr.length(); i++) {
            char c = dataStr.charAt(i);
            if (c >= 128 || CHARSET_REV[c] == -1) {
                throw new IllegalArgumentException("Invalid Bech32 character: " + c);
            }
            data[i] = (byte) CHARSET_REV[c];
        }

        Encoding encoding = verifyChecksum(hrp, data);
        if (encoding == null) {
            throw new IllegalArgumentException("Invalid Bech32 checksum");
        }

        // 去除校验和
        byte[] payload = Arrays.copyOfRange(data, 0, data.length - 6);

        return new DecodedBech32(hrp, payload, encoding);
    }

    /**
     * 解码 SegWit 地址
     */
    public static DecodedSegWitAddress decodeSegWitAddress(String hrp, String address) {
        DecodedBech32 decoded = decode(address);

        if (!decoded.hrp().equals(hrp)) {
            throw new IllegalArgumentException("Invalid HRP: expected " + hrp + ", got " + decoded.hrp());
        }

        byte[] data = decoded.data();
        if (data.length == 0) {
            throw new IllegalArgumentException("Empty data");
        }

        int witnessVersion = data[0];
        if (witnessVersion > 16) {
            throw new IllegalArgumentException("Invalid witness version: " + witnessVersion);
        }

        // 验证编码类型
        if (witnessVersion == 0 && decoded.encoding() != Encoding.BECH32) {
            throw new IllegalArgumentException("Witness v0 must use Bech32 encoding");
        }
        if (witnessVersion != 0 && decoded.encoding() != Encoding.BECH32M) {
            throw new IllegalArgumentException("Witness v1+ must use Bech32m encoding");
        }

        byte[] program = convertBits(Arrays.copyOfRange(data, 1, data.length), 5, 8, false);

        // 验证程序长度
        if (program.length < 2 || program.length > 40) {
            throw new IllegalArgumentException("Invalid witness program length: " + program.length);
        }
        if (witnessVersion == 0 && program.length != 20 && program.length != 32) {
            throw new IllegalArgumentException("Invalid witness v0 program length: " + program.length);
        }
        if (witnessVersion == 1 && program.length != 32) {
            throw new IllegalArgumentException("Invalid witness v1 program length: " + program.length);
        }

        return new DecodedSegWitAddress(witnessVersion, program, decoded.encoding());
    }

    private static String encodeInternal(String hrp, byte[] data, Encoding encoding) {
        byte[] checksum = createChecksum(hrp, data, encoding);
        byte[] combined = new byte[data.length + checksum.length];
        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(checksum, 0, combined, data.length, checksum.length);

        StringBuilder sb = new StringBuilder(hrp.length() + 1 + combined.length);
        sb.append(hrp).append('1');
        for (byte b : combined) {
            sb.append(CHARSET.charAt(b));
        }
        return sb.toString();
    }

    private static byte[] createChecksum(String hrp, byte[] data, Encoding encoding) {
        byte[] values = new byte[hrpExpand(hrp).length + data.length + 6];
        byte[] hrpExp = hrpExpand(hrp);
        System.arraycopy(hrpExp, 0, values, 0, hrpExp.length);
        System.arraycopy(data, 0, values, hrpExp.length, data.length);

        int constant = encoding == Encoding.BECH32 ? BECH32_CONST : BECH32M_CONST;
        int polymod = polymod(values) ^ constant;

        byte[] checksum = new byte[6];
        for (int i = 0; i < 6; i++) {
            checksum[i] = (byte) ((polymod >> (5 * (5 - i))) & 31);
        }
        return checksum;
    }

    private static Encoding verifyChecksum(String hrp, byte[] data) {
        byte[] values = new byte[hrpExpand(hrp).length + data.length];
        byte[] hrpExp = hrpExpand(hrp);
        System.arraycopy(hrpExp, 0, values, 0, hrpExp.length);
        System.arraycopy(data, 0, values, hrpExp.length, data.length);

        int polymod = polymod(values);
        if (polymod == BECH32_CONST) {
            return Encoding.BECH32;
        }
        if (polymod == BECH32M_CONST) {
            return Encoding.BECH32M;
        }
        return null;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] result = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            result[i] = (byte) (hrp.charAt(i) >> 5);
            result[hrp.length() + 1 + i] = (byte) (hrp.charAt(i) & 31);
        }
        result[hrp.length()] = 0;
        return result;
    }

    private static int polymod(byte[] values) {
        int[] gen = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        int chk = 1;
        for (byte v : values) {
            int top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v & 0xff);
            for (int i = 0; i < 5; i++) {
                if (((top >> i) & 1) == 1) {
                    chk ^= gen[i];
                }
            }
        }
        return chk;
    }

    /**
     * 位转换（用于 witness program 编码/解码）
     */
    public static byte[] convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int maxv = (1 << toBits) - 1;

        for (byte b : data) {
            int value = b & 0xff;
            if ((value >> fromBits) != 0) {
                throw new IllegalArgumentException("Invalid data range");
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result.write((acc >> bits) & maxv);
            }
        }

        if (pad) {
            if (bits > 0) {
                result.write((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new IllegalArgumentException("Invalid padding");
        }

        return result.toByteArray();
    }

    /**
     * 解码后的 Bech32 数据
     */
    public record DecodedBech32(String hrp, byte[] data, Encoding encoding) {
        public DecodedBech32 {
            data = Arrays.copyOf(data, data.length);
        }

        public byte[] data() {
            return Arrays.copyOf(data, data.length);
        }
    }

    /**
     * 解码后的 SegWit 地址数据
     */
    public record DecodedSegWitAddress(int witnessVersion, byte[] witnessProgram, Encoding encoding) {
        public DecodedSegWitAddress {
            witnessProgram = Arrays.copyOf(witnessProgram, witnessProgram.length);
        }

        public byte[] witnessProgram() {
            return Arrays.copyOf(witnessProgram, witnessProgram.length);
        }
    }
}

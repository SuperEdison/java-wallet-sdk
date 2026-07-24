package io.github.superedison.web3.chain.spi.signing;

import java.math.BigInteger;

/** secp256k1 外部签名的标量范围与 low-S 规范性校验。 */
public final class Secp256k1SignatureValidator {

    private static final BigInteger CURVE_ORDER =
            new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    private static final BigInteger HALF_CURVE_ORDER = CURVE_ORDER.shiftRight(1);

    private Secp256k1SignatureValidator() {}

    /**
     * 要求签名满足 {@code 1 <= r < n} 且 {@code 1 <= s <= n/2}。
     *
     * <p>拒绝 high-S 可避免同一签名者、同一消息存在两组不同的紧凑签名字节。
     */
    public static void requireCanonical(byte[] r, byte[] s) {
        if (r == null || r.length != 32) {
            throw new IllegalArgumentException("r must be 32 bytes");
        }
        if (s == null || s.length != 32) {
            throw new IllegalArgumentException("s must be 32 bytes");
        }

        BigInteger rValue = new BigInteger(1, r);
        if (rValue.signum() == 0 || rValue.compareTo(CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("r must be in the range [1, n - 1]");
        }

        BigInteger sValue = new BigInteger(1, s);
        if (sValue.signum() == 0 || sValue.compareTo(HALF_CURVE_ORDER) > 0) {
            throw new IllegalArgumentException("s must be in the low-S range [1, n / 2]");
        }
    }

    /** 消息与 typed-data 的 65 字节签名必须使用规范 legacy v（27/28）。 */
    public static void requireCanonicalLegacyV(byte[] signature) {
        if (signature == null || signature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        int v = signature[64] & 0xff;
        if (v != 27 && v != 28) {
            throw new IllegalArgumentException("Compact message signature v must be 27 or 28");
        }
    }
}

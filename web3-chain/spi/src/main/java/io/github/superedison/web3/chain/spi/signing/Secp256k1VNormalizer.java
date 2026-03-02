package io.github.superedison.web3.chain.spi.signing;

/**
 * secp256k1 签名 v 字段规范化工具。
 *
 * 支持三种常见输入格式：
 * - recovery id：0/1（也兼容 2/3，按奇偶折叠）
 * - legacy v：27/28
 * - EIP-155 v：chainId * 2 + 35/36
 */
public final class Secp256k1VNormalizer {

    private static final long LEGACY_V_BASE = 27L;
    private static final long EIP155_V_BASE = 35L;

    private Secp256k1VNormalizer() {}

    /**
     * 将任意支持的 v 表示转换为 recovery id (0/1)。
     */
    public static int toRecoveryId(long v) {
        if (v < 0) {
            throw new IllegalArgumentException("v must be non-negative, got: " + v);
        }
        if (v <= 3) {
            return (int) (v & 1L);
        }
        if (v == 27 || v == 28) {
            return (int) (v - LEGACY_V_BASE);
        }
        if (v >= EIP155_V_BASE) {
            return (int) ((v - EIP155_V_BASE) & 1L);
        }
        throw new IllegalArgumentException("Unsupported v value: " + v);
    }

    /**
     * 将任意支持的 v 表示转换为 legacy v (27/28)。
     */
    public static int toLegacyV(long v) {
        return (int) (LEGACY_V_BASE + toRecoveryId(v));
    }

    /**
     * 将任意支持的 v 表示转换为 EIP-155 v。
     */
    public static long toEip155V(long v, long chainId) {
        if (chainId < 0) {
            throw new IllegalArgumentException("chainId must be non-negative, got: " + chainId);
        }
        long chainPart;
        try {
            chainPart = Math.multiplyExact(chainId, 2L);
            chainPart = Math.addExact(chainPart, EIP155_V_BASE);
            return Math.addExact(chainPart, toRecoveryId(v));
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("chainId is too large for EIP-155 v: " + chainId, e);
        }
    }
}

package io.github.superedison.web3.chain.tron.internal;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * TRON 签名内部实现
 * 65 字节格式：r (32) + s (32) + v (1)
 */
public final class TronSignature implements Signature {

    private final byte[] r;
    private final byte[] s;
    private final int v;

    private TronSignature(byte[] r, byte[] s, int v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    /**
     * 从恢复 ID 创建签名
     * @param r 32 字节 r 值
     * @param s 32 字节 s 值
     * @param recoveryId 恢复 ID (0-3)
     * @return TronSignature 实例
     */
    public static TronSignature fromRecoveryId(byte[] r, byte[] s, int recoveryId) {
        if (r == null || r.length != 32) {
            throw new IllegalArgumentException("r must be 32 bytes");
        }
        if (s == null || s.length != 32) {
            throw new IllegalArgumentException("s must be 32 bytes");
        }
        if (recoveryId < 0 || recoveryId > 3) {
            throw new IllegalArgumentException("recoveryId must be 0-3");
        }
        // TRON 使用 27/28 作为 v 值
        int v = 27 + recoveryId;
        return new TronSignature(Arrays.copyOf(r, 32), Arrays.copyOf(s, 32), v);
    }

    /**
     * 从 65 字节紧凑格式解析
     * @param signature 65 字节签名 (r + s + v)
     * @return TronSignature 实例
     */
    public static TronSignature fromCompact(byte[] signature) {
        if (signature == null || signature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        int v = signature[64] & 0xFF;
        return new TronSignature(r, s, v);
    }

    /**
     * 从 Secp256k1Signature 创建
     * @param sig Secp256k1Signer.Secp256k1Signature 实例
     * @return TronSignature 实例
     */
    public static TronSignature fromSecp256k1Signature(io.github.superedison.web3.crypto.ecc.Secp256k1Signer.Secp256k1Signature sig) {
        return fromRecoveryId(sig.r(), sig.s(), sig.v());
    }

    @Override
    public byte[] bytes() {
        byte[] result = new byte[65];
        System.arraycopy(r, 0, result, 0, 32);
        System.arraycopy(s, 0, result, 32, 32);
        result[64] = (byte) v;
        return result;
    }

    @Override
    public SignatureScheme scheme() {
        return SignatureScheme.ECDSA_SECP256K1;
    }

    public byte[] getR() {
        return Arrays.copyOf(r, r.length);
    }

    public byte[] getS() {
        return Arrays.copyOf(s, s.length);
    }

    public int getV() {
        return v;
    }

    /**
     * 获取恢复 ID (0-3)
     */
    public int getRecoveryId() {
        return v - 27;
    }

    public BigInteger getRBigInt() {
        return new BigInteger(1, r);
    }

    public BigInteger getSBigInt() {
        return new BigInteger(1, s);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TronSignature that)) return false;
        return v == that.v && Arrays.equals(r, that.r) && Arrays.equals(s, that.s);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(r);
        result = 31 * result + Arrays.hashCode(s);
        result = 31 * result + v;
        return result;
    }

    @Override
    public String toString() {
        return "TronSignature{r=..., s=..., v=" + v + "}";
    }
}
